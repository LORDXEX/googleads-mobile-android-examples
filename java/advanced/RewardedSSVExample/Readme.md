**To start with Java :**

- `cd spring-boot`
- `./gradlew bootRun`
- go to `localhost:8080`

**To start with Docker:**

- `docker-compose up --build`
- go to `localhost:8080`

**To test a different signature and message:**

- Send a `POST` request to `localhost:8080/verify` with JSON body:
 ```
 {"reward_url":"https://callbackUrl?""}
```
