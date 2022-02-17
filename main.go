package main

import (
	"crypto/tls"
	"fmt"
	ldap3 "github.com/go-ldap/ldap/v3"
	"github.com/x-auth/common/models"
	"github.com/x-auth/common/plugins"
	"log"
	"strconv"
)

type Plugin struct {
	// config
	raw_cfg map[string]string
	// mapping
	name         string
	family_name  string
	given_name   string
	nickname     string
	email        string
	phone_number string
	groups       string

	// connection config
	bind_dn    string
	bind_pw    string
	base_dn    string
	filter     string
	connection *ldap3.Conn
}

func (p *Plugin) Login(username string, password string) (models.Profile, error) {
	// bind with the bind dn
	err := p.connection.Bind(p.bind_dn, p.bind_pw)
	if err != nil {
		log.Println(err)
		return models.Profile{}, err
	}

	// set up search for the given username
	searchRequest := ldap3.NewSearchRequest(
		p.base_dn,
		ldap3.ScopeWholeSubtree, ldap3.NeverDerefAliases,
		sizeLimit, timeLimit,
		typesOnly,
		fmt.Sprintf("(&%s(%s=%s))", p.filter, p.email, username),
		[]string{"dn"},
		nil,
	)

	// run the search
	searchResult, err := p.connection.Search(searchRequest)
	if err != nil {
		log.Println(err)
		return models.Profile{}, err
	}

	// get the first entry of the searchResult
	numEntries := len(searchResult.Entries)
	if numEntries != 1 {
		return models.Profile{}, err
	}

	// Bind the user to verify the password
	userdn := searchResult.Entries[0].DN
	err = p.connection.Bind(userdn, password)
	if err != nil {
		log.Println(err)
		return models.Profile{}, err
	}

	userSearchRequest := ldap3.NewSearchRequest(
		userdn,
		ldap3.ScopeBaseObject,
		ldap3.NeverDerefAliases,
		sizeLimit, timeLimit,
		typesOnly,
		"(objectClass=*)",
		[]string{p.name, p.family_name, p.given_name, p.nickname, p.email, p.phone_number},
		nil,
	)

	// run the search
	userSearchResult, err := p.connection.Search(userSearchRequest)
	if err != nil {
		log.Println(err)
		return models.Profile{}, err
	}

	if len(userSearchResult.Entries) != 1 {
		return models.Profile{}, err
	}

	// parse the attributes for internal profile
	userAttrs := userSearchResult.Entries[0].Attributes

	// parse the groups
	groups := getGroups(getAttr(userAttrs, p.groups))

	profile := models.Profile{
		Name:        getAttr(userAttrs, p.name)[0],
		FamilyName:  getAttr(userAttrs, p.family_name)[0],
		GivenName:   getAttr(userAttrs, p.given_name)[0],
		NickName:    getAttr(userAttrs, p.nickname)[0],
		Email:       getAttr(userAttrs, p.email)[0],
		PhoneNumber: getAttr(userAttrs, p.phone_number)[0],
		Groups:      groups,
	}

	return profile, nil
}

func (p *Plugin) Connect(cfg map[string]string) error {
	log.Println("connecting")
	var useTLS, enableSSL bool
	if cfg["encryption"] == "tls" {
		useTLS = true
		enableSSL = false
	} else if cfg["encryption"] == "ssl" {
		useTLS = false
		enableSSL = true
	} else {
		useTLS = false
		enableSSL = false
	}

	skipVerify, err := strconv.ParseBool(cfg["skip_verify"])
	if err != nil {
		return err
	}

	if useTLS {
		p.connection, err = ldap3.DialURL("ldap://" + cfg["host"])
		if err != nil {
			return err
		}
		err = p.connection.StartTLS(&tls.Config{InsecureSkipVerify: skipVerify})
		if err != nil {
			return err
		}
	} else if enableSSL {
		tlsConf := &tls.Config{InsecureSkipVerify: skipVerify}
		p.connection, err = ldap3.DialTLS("tcp", cfg["host"], tlsConf)
		if err != nil {
			return err
		}
	} else {
		p.connection, err = ldap3.Dial("tcp", cfg["host"])
		if err != nil {
			return err
		}
	}

	return nil
}

func NewPlugin(cfg map[string]string) (plugins.AuthPlugin, error) {
	plug := Plugin{
		raw_cfg:      cfg,
		name:         cfg["name"],
		family_name:  cfg["family_name"],
		given_name:   cfg["given_name"],
		nickname:     cfg["nickname"],
		email:        cfg["email"],
		phone_number: cfg["phone_number"],
		bind_dn:      cfg["bind_dn"],
		bind_pw:      cfg["bind_pw"],
		base_dn:      cfg["base_dn"],
		groups:       cfg["groups"],
		filter:       cfg["filter"],
	}

	err := plug.Connect(plug.raw_cfg)
	if err != nil {
		return &Plugin{}, err
	}

	return &plug, nil
}
