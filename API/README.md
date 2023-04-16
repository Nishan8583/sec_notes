# API Security
## Passive Recon
- Gitub: https://github.com/ 
- Postman Explore: https://www.postman.com/explore/apis
- ProgrammableWeb API Directory: https://www.programmableweb.com/apis/directory 
- APIs Guru: https://apis.guru/ 
- Public APIs Github Project: https://github.com/public-apis/public-apis 
- RapidAPI Hub: https://rapidapi.com/search/ 
https://university.apisec.ai/products/api-penetration-testing/categories/2150259092/posts/2157852412
- inurl:"/wp-json/wp/v2/users"
- intitle:"index.of" intext:"api.txt"
- inurl:"/api/v1" intext:"index of /"
- github look for exposed keys
- shodan
- wayback for old documentations

## Active Recon
- nmap
- gobuster
- amass enum -active -d target-name.com |grep api
- kiterunner
- Browser devtools

## Endpoint analysis
- Postman, create a collection, start saving proxy, route browser traffic thru it, walk through the web app, save it.
- Use mitmproxy
- mitmpeoxy2swagger
    - `$ mitmweb` starts the peoxy.
    - Route traffic through it.
    - Save flow
    - `$sudo mitmproxy2swagger -i /Downloads/flows -o spec.yml -p http://crapi.apisec.ai -f flow` This will first capture everything and save in spec.yaml
    - Change it to remove `ignore:` for the things we want.
    - Run the command again with extra `--examples` in the end to add more information
    - To install mitmproxy2swagger, follow the guide `https://github.com/alufers/mitmproxy2swagger`. The python file will be installed in `~/.local/bin`
    - Now you can import the new spec.yml in `swagger` editor or `postman`
    - Now the entire API stuff will be a colllection, edit collection to have `environment variables`, `scripts` to auto replace a string for fuzzing
    - Also add `tests` (lets say to check if status is 200) and run entire colleciton at once, and see response.
    - Variables in request are in format `{{variable_name}}`, u can also set it by right click and set it.
    - Set `inherit auth from parent`.
- OWASP, go through app, put spider on, then later turn attack mode on, and scan
