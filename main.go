package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	v1 "github.com/Permify/permify-go/generated/base/v1"
	permify "github.com/Permify/permify-go/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var client *permify.Client
var users = map[string]string{"user1": "password1", "user2": "password2"}
var sessions = map[string]string{}
var sr *v1.SchemaWriteResponse
var rr *v1.DataWriteResponse

var schemaVersion string
var snapToken string

func init() {
	var err error
	client, err = permify.NewClient(
		permify.Config{
			Endpoint: "localhost:3478",
		},
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		log.Fatalf("Failed to create Permify client: %v", err)
	}
	setupPermify()
	setupRoutes()
}

func main() {
	log.Println("Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func setupPermify() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	schema := `
	entity user {}
	entity organization {
		relation group @group
		relation document @document
		relation administrator @user @group#direct_member @group#manager
		relation direct_member @user
		permission admin = administrator
		permission member = direct_member or administrator or group.member
	}
	entity group {
		relation manager @user @group#direct_member @group#manager
		relation direct_member @user @group#direct_member @group#manager
		permission member = direct_member or manager
	}
	entity document {
		relation org @organization
		relation viewer @user @group#direct_member @group#manager
		relation manager @user @group#direct_member @group#manager
		action edit = manager or org.admin
		action view = viewer or manager or org.admin
	}`

	sr, err := client.Schema.Write(ctx, &v1.SchemaWriteRequest{
		TenantId: "t1",
		Schema:   schema,
	})
	if err != nil {
		log.Fatalf("Failed to write schema: %v", err)
	}
	schemaVersion = sr.SchemaVersion
	log.Printf("Schema Data written: %v", schemaVersion)

	rr, err = client.Data.Write(ctx, &v1.DataWriteRequest{
		TenantId: "t1",
		Metadata: &v1.DataWriteRequestMetadata{
			SchemaVersion: sr.SchemaVersion,
		},
		Tuples: []*v1.Tuple{
			{
				Entity:   &v1.Entity{Type: "document", Id: "1"},
				Relation: "viewer",
				Subject:  &v1.Subject{Type: "user", Id: "user1"},
			},
		},
	})

	if err != nil {
		log.Fatalf("Failed to write relationships: %v", err)
	}
	snapToken = rr.SnapToken
	log.Printf("Relation Data written: %v", snapToken)
}

func setupRoutes() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := `<!DOCTYPE html><html><head><title>Login</title></head><body>
            <h1>Login</h1>
            <form action="/login" method="post">
                Username: <input type="text" name="username"><br>
                Password: <input type="password" name="password"><br>
                <input type="submit" value="Login">
            </form>
        </body></html>`
		fmt.Fprintln(w, tmpl)
	})
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username, password := r.Form.Get("username"), r.Form.Get("password")
		if correctPassword, ok := users[username]; ok && password == correctPassword {
			sessionToken := fmt.Sprintf("%s-%d", username, time.Now().Unix())
			sessions[sessionToken] = username
			http.SetCookie(w, &http.Cookie{Name: "session_token", Value: sessionToken, Path: "/"})
			http.Redirect(w, r, "/protected", http.StatusSeeOther)
		} else {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		}
	})
	http.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("session_token"); err == nil {
			if username, ok := sessions[cookie.Value]; ok {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cr, err := client.Permission.Check(ctx, &v1.PermissionCheckRequest{
					TenantId:   "t1",
					Entity:     &v1.Entity{Type: "document", Id: "1"},
					Permission: "view",
					Subject:    &v1.Subject{Type: "user", Id: username},
					Metadata: &v1.PermissionCheckRequestMetadata{
						SnapToken:     snapToken,
						SchemaVersion: schemaVersion,
						Depth:         50,
					},
				})
				if err != nil || cr.Can != v1.CheckResult_CHECK_RESULT_ALLOWED {
					http.Error(w, "Access Denied", http.StatusForbidden)
					log.Println("error: ", err)
					return
				}
				fmt.Fprintf(w, "Welcome %s, you have access to view this document.", username)
				log.Println("cr log: ", cr)
				return
			}
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
