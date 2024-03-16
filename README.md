# Sync AD LDAP users to postgresql 
This script matches Active Directory security groups to psql databases. They must match exactly.

The matched users will be added as Roles in psql with R/W access to their respective databases. The users will be able to authenticate via LDAP to databases that have a matching AD security group. The users will not have "connect" perms on any DBs unless they are a member of a matching AD group.

It's up to you to get psql and LDAP authentication working.
