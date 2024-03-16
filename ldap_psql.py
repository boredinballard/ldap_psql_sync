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

# PostgreSQL configuration
PG_DSN = 'dbname=postgres user=postgres password=postgres'

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
    with psycopg2.connect(dsn) as conn:
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        with conn.cursor() as cur:
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            databases = [row[0] for row in cur.fetchall()]
            for group, members in group_members.items():
                if group in databases:
                    for member in members:
                        cur.execute(f"DO $$ BEGIN CREATE ROLE \"{member}\" LOGIN; EXCEPTION WHEN DUPLICATE_OBJECT THEN RAISE NOTICE 'not creating role {member} -- it already exists'; END $$;")
                        # Grant CONNECT on the database
                        cur.execute(f"GRANT CONNECT ON DATABASE \"{group}\" TO \"{member}\";")
                        # Set default privileges (this assumes public schema, adjust as needed)
                        cur.execute(f"GRANT USAGE ON SCHEMA public TO \"{member}\";")
                        cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{member}\";")
                        cur.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \"{member}\";")
                        print(f"Granted LOGIN and read-write access to '{member}' for database '{group}'.")

if __name__ == '__main__':
    group_members = get_ad_groups_and_members(LDAP_SERVER, LDAP_USER, LDAP_PASSWORD, LDAP_SEARCH_BASE)
    create_pg_roles_for_group_members(PG_DSN, group_members)