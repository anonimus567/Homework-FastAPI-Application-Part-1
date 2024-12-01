# My code

## Endpoint to retrieve information about aplication and creator
```python
@app.get('/info', response_class=HTMLResponse)
def get_information_about_current_program_and_user(request: Request):
    creator = list(my_users.values())
    info = {
        "web app": "Web application for retriving  CVE Information from JSON file",
        "creator": creator 
    }
    return templates.TemplateResponse("info.html", {"request": request, "info": info})
```
## Result
![Screenshot 2024-12-01 235753](https://github.com/user-attachments/assets/a69f6540-95cb-4527-8d2f-3aa6426ee4d8)

## Endpoint to get all CVEs for last five days
```python
@app.get("/get/all", response_class=HTMLResponse)
def get_all_cve_for_last_five_days(request: Request):
    json_path = "known_exploited_vulnerabilities.json"
    with open(json_path, "r") as file:
        json_data = json.load(file)
    desc_of_cves = json_data.get("vulnerabilities", [])
    date_pattern = re.compile(r"2024-11-(30|29|28|27|26|25)")
    result_of_searching = []
    count = 0
    for vuln in desc_of_cves:
        date = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
        vuln["dateAdded"] = date.strftime("%Y-%m-%d")
        if date_pattern.search(vuln["dateAdded"]):
            result_of_searching.append(vuln)
            count += 1
            if count == 40:  
                break
    return templates.TemplateResponse("all_cves.html", {"request": request, "result_of_searching": result_of_searching})
```
## Result
![Screenshot 2024-12-02 000223](https://github.com/user-attachments/assets/01338d9e-c344-4a6c-b065-4a4ee8289cb3)

## Endpoint to get 10 newest CVEs 
```python
@app.get("/get/new", response_class=HTMLResponse)
def get_ten_latest_cve(request: Request):
    with open("known_exploited_vulnerabilities.json", "r") as file:
        data = json.load(file)
        desc_of_vuln = data["vulnerabilities"]

        newest_vulnerabilities=[]
        sorted_data = sorted(desc_of_vuln, key=itemgetter("dateAdded"), reverse=True)
        count = 0

        for vuln in sorted_data:
           newest_vulnerabilities.append(vuln)
           count += 1
           if count == 10:
             break

        return templates.TemplateResponse("new_cves.html", {"request": request, "newest_vulnerabilitie": newest_vulnerabilities})
```
## Result
![Screenshot 2024-12-02 000223](https://github.com/user-attachments/assets/cdde8590-3266-42bd-b325-2b2258e31bbd)
## Endpoint to get 10 known CVEs 
```python
@app.get("/get/known")
def get_ten_known_cve(request: Request):
    with open("known_exploited_vulnerabilities.json", "r") as file:
        json_data = json.load(file)
        desc_of_cves = json_data.get("vulnerabilities", [])

        known_cves = []
        count = 0
        
        for vuln in desc_of_cves:
            if vuln.get("knownRansomwareCampaignUse") == "Known":
                known_cves.append(vuln)
                count += 1
                if count == 10:
                    break
        return templates.TemplateResponse(
        "known_cves.html", {"request": request, "known_cves": known_cves})
```
## Result
<img width="928" alt="image" src="https://github.com/user-attachments/assets/c94eca76-65b6-4b3c-8993-4089348129a6">

## Endpoint to search CVEs with query 
```python
@app.get("/get", response_class=HTMLResponse)
def get_results_with_query(request: Request, query: str ):
    if not re.match(r"([a-zA-Z0-9]+(\s[a-zA-Z0-9]+)?)", query):
        raise HTTPException(status_code=400, detail="Your keyphrase in url includes forbidden symbols. Please use only letters and digits.")
 
    with open("known_exploited_vulnerabilities.json", "r") as file:
        json_data = json.load(file)
    
    pattern = re.compile(query)

    result_of_searching = []

    for vuln in json_data["vulnerabilities"]:
        description = vuln.get("shortDescription", "")        
        if pattern.search(description):
             result_of_searching.append(vuln)

    return templates.TemplateResponse("search_for_query.html",{"request": request, "query": query, "result_of_searching": result_of_searching})
```
## Result
<img width="948" alt="image" src="https://github.com/user-attachments/assets/bb89eea8-86d0-4ee8-b0cf-5068817878ae">


    
            
