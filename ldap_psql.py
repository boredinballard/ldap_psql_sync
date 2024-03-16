import ldap3
from ldap3 import Server, Connection, ALL, SUBTREE
import psycopg2
import psycopg2.extras

# LDAP configuration
LDAP_SERVER = 'ldap://ldapserver'
LDAP_USER = 'cn=ldapuser,ou=users,ou=orgunit,dc=domain,dc=local'  # Adjust this
LDAP_PASSWORD = 'ldappassword'
LDAP_SEARCH_BASE = 'OU=securitygroups,OU=orgunit,DC=domain,DC=local'  # Adjust this
LDAP_SEARCH_FILTER = '(objectClass=group)'  # Adjust this for your LDAP schema

# Adjusted PostgreSQL configuration for clarity and security
PG_DSN = {
    'dbname': 'postgres', 
    'user': 'postgres', 
    'password': 'postgres',
    'host': 'localhost'  # Specify the host if not local
}

def get_ad_groups_and_members(server, user, password, search_base):
    group_members = {}
    server = Server(server, get_info=ALL)
    conn = Connection(server, user, password, auto_bind=True)
    conn.search(search_base, '(objectClass=group)', attributes=['cn', 'member'])
    for entry in conn.entries:
        group_name = entry.cn.value
        members = entry.member.values if entry.member else []
        member_usernames = []
        for member_dn in members:
            conn.search(member_dn, '(objectClass=person)', search_scope=SUBTREE, attributes=['sAMAccountName'])
            for user_entry in conn.entries:
                member_usernames.append(user_entry.sAMAccountName.value)
        group_members[group_name] = member_usernames
    conn.unbind()
    return group_members

def create_pg_roles_for_group_members(dsn, group_members):
    allowed_members = set(member for members in group_members.values() for member in members)

    with psycopg2.connect(**dsn) as conn:
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        with conn.cursor() as cur:
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            databases = [row[0] for row in cur.fetchall()]

    for db in databases:
     # Skip the "postgres" database to preserve its PUBLIC permissions
        if db == "postgres":
            continue
            
        dsn_db = dsn.copy()
        dsn_db["dbname"] = db
        with psycopg2.connect(**dsn_db) as conn:
            conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
            with conn.cursor() as cur:
                # Revoke CONNECT permission from PUBLIC for the database
                cur.execute(f"REVOKE CONNECT ON DATABASE \"{db}\" FROM PUBLIC;")

                # List all roles with CONNECT permission to the database
                cur.execute("SELECT rolname FROM pg_roles WHERE rolcanlogin = true;")
                all_login_roles = {row[0] for row in cur.fetchall()}

                # Determine allowed members for this database and revoke from roles not in allowed_members_for_db
                allowed_members_for_db = set(group_members.get(db, []))
                for role in all_login_roles - allowed_members_for_db:
                    cur.execute(f"REVOKE CONNECT ON DATABASE \"{db}\" FROM \"{role}\";")

                # Grant permissions to allowed members for this database
                for member in allowed_members_for_db:
                    # Ensure role exists and grant CONNECT
                    cur.execute(f"DO $$ BEGIN CREATE ROLE \"{member}\" LOGIN; EXCEPTION WHEN DUPLICATE_OBJECT THEN RAISE NOTICE 'not creating role {member} -- it already exists'; END $$;")
                    cur.execute(f"GRANT CONNECT ON DATABASE \"{db}\" TO \"{member}\";")
                    
                    # Grant USAGE and read-write permissions
                    cur.execute(f"""
                        GRANT USAGE ON SCHEMA public TO "{member}";
                        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO "{member}";
                        GRANT USAGE, UPDATE ON ALL SEQUENCES IN SCHEMA public TO "{member}";
                    """)
                    print(f"Updated permissions for '{member}' on database '{db}'.")

if __name__ == '__main__':
    group_members = get_ad_groups_and_members(LDAP_SERVER, LDAP_USER, LDAP_PASSWORD, LDAP_SEARCH_BASE)
    create_pg_roles_for_group_members(PG_DSN, group_members)
