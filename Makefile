build:
	go build -buildmode=plugin -o ldap.so .

install:
	cp ldap.so /var/x-auth/plugins