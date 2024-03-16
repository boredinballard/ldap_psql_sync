# Sync AD LDAP users to postgresql 
This script matches Active Directory security groups to psql databases. They must match exactly.
The matched users will be added as Roles in psql with LOGIN and read/write perms to their respective database.

It's up to you to get psql and LDAP authentication working.
