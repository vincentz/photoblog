package main

import (
	"net/http"
	"time"
)

func loggedIn(req *http.Request) bool {
	c, err := req.Cookie("session")
	if err != nil {
		return false
	}
	un := dbSessions[c.Value].un
	_, ok := dbUsers[un]
	return ok
}

func cleanSessions() {
	// fmt.Println("BEFORE CLEAN") // for demonstration purposes
	for k, v := range dbSessions {
		if time.Now().Sub(v.lastActivity) > (time.Second * 30) {
			delete(dbSessions, k)
		}
	}
	dbSessionCleaned = time.Now()
	// fmt.Println("AFTER CLEAN") // for demonstration purposes
}
