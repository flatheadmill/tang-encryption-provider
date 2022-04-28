
## Run Tang Server
```shell
docker run -d -p 8080:80 --name tang \
-v tang-db:/var/db/tang \
 malaiwah/tang
```

### Extract Thumbprint from Tang server
#### Install
- jq
- jose

#### Run
```shell
curl -s http://localhost:8080/adv | jq -r '.payload' | base64 --decode | jq '.keys[0]' | jose jwk thp -i -
```

## Run Example Encrypt -> Decrypt
```shell
cd cmd
./test_run.sh
```