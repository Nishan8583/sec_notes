# DAST

# 1. Spider
- `Tools -> spider`, recurse to go recursively, 

# 2. Scanning
- `Analyze -> Scan Policy Manager`, `Injection` diselect what u do want want.

# 3. API
- If u find openapi .json definition file.
**Import -> Import an OpenAPI definition from a URL**

# 4. CICD
- Integrating using owasp zap docker
```none
docker pull owasp/zap2docker-stable
docker run -t owasp/zap2docker-stable zap-baseline.py -t https://www.example.com
```
<!--StartFragment-->

- U can include such command in jenkins file.
```json
node{

  git branch: "main", url: "http://172.17.0.1:3000/thm/simple-webapp"

  stage ('Build the Docker image') {
    sh "echo building the image..."
    sh "docker build --tag simple-webapp:latest ."
    sh "echo building image complete."

  }

  stage ('Deploy the Docker image') {
    sh "echo Deploying the container..."
    sh " docker rm -f simple-webapp"
    sh "docker run -d -p 8082:80 --name simple-webapp simple-webapp:latest "
    sh "echo Container successfully deployed."

  }
  stage ('Scan with OWASP ZAP') {
    sh "mkdir -p zap-reports"
    sh "chmod 777 zap-reports"
    sh "docker run -v \$(pwd)/zap-reports:/zap/wrk/:rw -t owasp/zap2docker-stable zap-baseline.py -t http://172.17.0.1:8082/ -r baseline-simple-webapp-${env.BUILD_NUMBER}.html"
  }

}
```
- In jenkins, clikck the build, click workspace, and then zap-reports.
# Further stuffs to exploire
- Gittea
- jenkin