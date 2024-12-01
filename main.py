from fastapi import FastAPI, Query, HTTPException, Request
from datetime import datetime
from pydantic import BaseModel
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import json
import re
from operator import itemgetter

app = FastAPI()#initializing the FastAPI application

templates = Jinja2Templates(directory="templates")# setting up Jinja2 template directory for rendering HTML responses

my_users = {'mariana': {'username': 'mariana', 'position': 'developer'}}# creating dictionary to save my users

class User(BaseModel):# defining  model to validate fields in dictionary
    username: str# username of the user
    position: str# position of the user (e.g., developer)

@app.post('/users')# endpoint to create a new user
def create_user(user: User):
    username = user.username # extracting username from the request
    my_users[username] = user.dict()# storing user data in the dictionary
    return  user

@app.get('/info', response_class=HTMLResponse)# endpoint for retrieving information about the application and its creator
def get_information_about_current_program_and_user(request: Request):
    creator = list(my_users.values())# getting  list of users
    info = {
        "web app": "Web application for retriving  CVE Information from JSON file", #defining information to be displayed
        "creator": creator 
    }
    return templates.TemplateResponse("info.html", {"request": request, "info": info})#returning  information page using info.html template


@app.get("/get/all", response_class=HTMLResponse)# endpoint for retrieving all CVEs added in the last five days
def get_all_cve_for_last_five_days(request: Request):
    json_path = "known_exploited_vulnerabilities.json"
    with open(json_path, "r") as file: #opening json file in read mode
        json_data = json.load(file)# loading data from the JSON file

    desc_of_cves = json_data.get("vulnerabilities", [])# getting the list of cves
    date_pattern = re.compile(r"2024-11-(30|29|28|27|26|25)")#defining pattern to match only last five days

    result_of_searching = []#creating list to store result of cves that match "date_pattern "
    count = 0#variable to limit results

 # iterating over vulnerabilities and adding  matching  with date pattern cves to result_of_searching list 
    for vuln in desc_of_cves: 
        date = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
        vuln["dateAdded"] = date.strftime("%Y-%m-%d")
        if date_pattern.search(vuln["dateAdded"]):
            result_of_searching.append(vuln)
            count += 1# when new cve is added to list count increase by one
            if count == 40: # if list of cves includes 40 cves iterating stops
                break

    return templates.TemplateResponse("all_cves.html", {"request": request, "result_of_searching": result_of_searching})#returning  list of cves for last five days using all_cves.html template

@app.get("/get/new", response_class=HTMLResponse)# endpoint for retrieving  ten latest CVEs
def get_ten_latest_cve(request: Request):
    with open("known_exploited_vulnerabilities.json", "r") as file: 
        data = json.load(file)
        desc_of_vuln = data["vulnerabilities"]

        newest_vulnerabilities=[]#creating list for storing results
        sorted_data = sorted(desc_of_vuln, key=itemgetter("dateAdded"), reverse=True)# sorting by dates 
        count = 0
         #iterating through newest cves and adding 10 cves to list newest_vulnerabilities
        for vuln in sorted_data:
           newest_vulnerabilities.append(vuln)
           count += 1
           if count == 10:
             break

        return templates.TemplateResponse("new_cves.html", {"request": request, "newest_vulnerabilitie": newest_vulnerabilities})#returning  list of 10 newest cves  using new_cves.html template
# endpoint for retrieving ten known CVEs 
@app.get("/get/known")
def get_ten_known_cve(request: Request):
    with open("known_exploited_vulnerabilities.json", "r") as file:
        json_data = json.load(file)
        desc_of_cves = json_data.get("vulnerabilities", [])

        known_cves = []#creating list to save results
        count = 0
        # iterating each cve and finding vulnerabilities marked as "Known" 
        for vuln in desc_of_cves:
            if vuln.get("knownRansomwareCampaignUse") == "Known":
                known_cves.append(vuln)#adding known cve to result list
                count += 1
                if count == 10:# limiting to 10 results
                    break
        return templates.TemplateResponse(
        "known_cves.html", {"request": request, "known_cves": known_cves})# returning list of known cves using "known_cves.html" template

# endpoint to search cves with  query
@app.get("/get", response_class=HTMLResponse)
def get_results_with_query(request: Request, query: str ):
    if not re.match(r"([a-zA-Z0-9]+(\s[a-zA-Z0-9]+)?)", query):#regular expression to validate the query (one or two words with letters and digits only are allowed )
        raise HTTPException(status_code=400, detail="Your keyphrase in url includes forbidden symbols. Please use only letters and digits.")# error if user input is incorrect
 
    with open("known_exploited_vulnerabilities.json", "r") as file:
        json_data = json.load(file)
    
    pattern = re.compile(query) # compiling  query for regex search

    result_of_searching = []# creating list to save results
#iterating through all cves and searching for query in shortDescription
    for vuln in json_data["vulnerabilities"]:
        description = vuln.get("shortDescription", "")        
        if pattern.search(description): # if query matches pattern, cve is added to result list
             result_of_searching.append(vuln)

    return templates.TemplateResponse("search_for_query.html",{"request": request, "query": query, "result_of_searching": result_of_searching})# returning result list using serch_for_query.html template


    
            
