#Explanation of my code

from fastapi import FastAPI, Query, HTTPException, Request
from datetime import datetime
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import json
import re
from operator import itemgetter

app = FastAPI()

templates = Jinja2Templates(directory="templates")

###Creating dictionary that is used to store information about my application users
my_users = {
    'mariana': {'username': 'mariana', 'position': 'developer'}
}


class User(BaseModel):
    username: str
    position: str

@app.post('/users')
def create_user(user: User):
    username = user.username
    my_users[username] = user.dict()
    return  user

@app.get('/info', response_class=HTMLResponse)
def get_information_about_current_program_and_user(request: Request):
    creator = list(my_users.values())
    info = {
        "web app": "Web application for retriving  CVE Information from JSON file",
        "creator": creator 
    }
    return templates.TemplateResponse("info.html", {"request": request, "info": info})


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


    
            
