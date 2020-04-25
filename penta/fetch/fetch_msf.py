import concurrent.futures
import logging
import os
import random
import re
import time

from dateutil import parser
from db.db import DBInit, MsfDAO
from models.models import MsfRecord
import requests
from requests.exceptions import RequestException
import requests_html
from tqdm import tqdm
from utils import get_val

api_token = os.environ.get("GITHUB_TOKEN")
msf_module_path = os.environ.get("METASPLOIT_MODULE_PATH")
module_pape_limit = 5


class MsfCollector:
    def __init__(self):
        db_init = DBInit()
        self.msf_dao = MsfDAO(db_init.session)

        self.session = requests_html.HTMLSession()
        self.session.keep_alive = False
        self.headers = {
            'user-agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36',
        }

    # Request to the server for data crawling or scraping
    def request(self, url):
        time.sleep(random.uniform(0.5, 2.0))
        try:
            page = self.session.get(url, headers=self.headers)
            return page
        except RequestException:
            page = self.request(url)
            return page

    # Function call that executes an update
    def update(self):
        self.fetch()

    # Get the latest msf module list
    def fetch(self):
        url = "https://www.rapid7.com/db/modules"
        logging.info("Fetching {}".format(url))

        module_list_page = self.request(url)

        try:
            module_lists = module_list_page.html.xpath("//section[@class='vulndb__results']/a/@href")
            self.convert(module_lists)
        except Exception as e:
            logging.warning("Exception while parsing modules")
            logging.warning("{}".format(e))

    # Get the msf module list of the specified number of pages
    def traverse(self):
        module_lists = []
        for page_num in range(1, module_pape_limit + 1):
            url = "https://www.rapid7.com/db/?type=metasploit&page={}".format(page_num)
            logging.info("Fetching {}".format(url))

            module_list_page = self.request(url)

            try:
                modules = module_list_page.html.xpath("//section[@class='vulndb__results']/a/@href")
                for module in modules:
                    module_lists.append(module)
            except Exception as e:
                logging.warning("Exception while enumerating the list")
                logging.warning("{}".format(e))

        try:
            self.convert(module_lists)
        except Exception as e:
            logging.warning("Exception while parsing modules")
            logging.warning("{}".format(e))

    # Insert a record of each module to the database
    def convert(self, module_lists):
        items = module_lists
        logging.info("Fetched {} modules list".format(len(items)))
        logging.info("Inserting fetched modules...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(self.parse_msf_module, item): item for item in items}

            for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
                pass

        executor.shutdown()
        self.msf_dao.commit()
        logging.info("Successfully updated")

    # Extracts each element of HTML and converts it to a database model
    def parse_msf_module(self, item):
        url = "https://www.rapid7.com{}".format(item)
        module_item = self.request(url)

        if module_item.status_code != 200:
            msf_record = MsfRecord(module_name=item[11:])
            self.msf_dao.add(msf_record)

        element_xpath = {
            'module_title': '//div[@class="vulndb__detail-main"]/h3/text()',
            'module_url': '/html/head/link[@rel="canonical"]/@href',
            'module_devlink': '//section[contains(@class,"vulndb__solution")]/ul/li[1]/a/@href',
            'module_describe': '//div[contains(@class,"vulndb__detail-content")]/p/text()',
            'module_authors': '//div[contains(@class,"vulndb__detail-content")]/ul/li/text()',
            'module_references': '//section[contains(@class,"vulndb__references")]/ul/li//text()',
            'module_platforms': '//div[contains(@class,"vulndb__detail-content")]/p[2]/text()',
            'module_architectures': '//div[contains(@class,"vulndb__detail-content")]/p[3]/text()',
        }

        module_url = get_val(module_item.html.xpath(element_xpath["module_url"]))
        code_link = get_val(module_item.html.xpath(element_xpath["module_devlink"]))
        module_name = code_link[60:]
        module_title = get_val(module_item.html.xpath(element_xpath["module_title"]))
        module_describe_words = module_item.html.xpath(element_xpath["module_describe"])[0].split()
        module_describe = ' '.join(module_describe_words)

        module_authors = get_val(module_item.html.xpath(element_xpath["module_authors"]))

        module_references = get_val(module_item.html.xpath(element_xpath["module_references"]))
        module_cve = ""
        module_edb = ""

        # Extracting CVEs&EDBs from reference information
        if module_references is not None:
            cve_list = []
            edb_list = []
            pattern = "CVE-\d{4}-\d+|EDB-\d+"
            module_cve_edb_list = re.findall(pattern, module_references)
            exclusion_pattern = "CVE-\d{4}-\d+,?|EDB-\d+,?"
            module_references = re.sub(exclusion_pattern, "", module_references)

            for item in module_cve_edb_list:
                if "CVE" in item:
                    cve_list.append(item)
                elif "EDB" in item:
                    edb_list.append(item)

            if len(cve_list) >= 1:
                module_cve = ','.join(cve_list)
            if len(edb_list) >= 1:
                module_edb = ','.join(edb_list)

        module_platforms = get_val(module_item.html.xpath(element_xpath["module_platforms"]))
        module_architectures = get_val(module_item.html.xpath(
            element_xpath["module_architectures"]))

        modified_date = MsfCollector.get_modified_date(module_name)
        module_update_date = parser.parse(modified_date).strftime("%Y-%m-%d %H:%M:%S")
        module_collect_date = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        msf_record = MsfRecord(
            module_name=module_name,
            module_title=module_title,
            module_url=module_url,
            module_describe=module_describe,
            module_authors=module_authors,
            module_cve=module_cve,
            module_edb=module_edb,
            module_references=module_references,
            module_platforms=module_platforms,
            module_architectures=module_architectures,
            module_update_date=module_update_date,
            module_collect_date=module_collect_date
        )

        self.insert_record(msf_record)

    # Run a database query and add a record
    def insert_record(self, record):
        if self.msf_dao.exist(record.module_name):
            self.msf_dao.update(record)
        else:
            self.msf_dao.add(record)

    # Date of site info is not trustworthy, so refer to git's commit log
    @staticmethod
    def get_modified_date(module_name):
        url = "https://api.github.com/graphql"
        headers = {"Authorization": "token {}".format(api_token)}

        repo_args = 'owner: "rapid7", name: "metasploit-framework"'
        ref_args = 'qualifiedName: "refs/heads/master"'
        hist_args = 'first: 1, path: "{}"'.format(module_name)
        gqljson = {
            "query": """
                query {
                    repository(%(repo_args)s) {
                        ref(%(ref_args)s) {
                            target {
                                ... on Commit {
                                    history(%(hist_args)s) {
                                        edges {
                                            node {
                                                committedDate
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            """
            % dict(repo_args=repo_args, ref_args=ref_args, hist_args=hist_args)
        }

        r = requests.post(url=url, json=gqljson, headers=headers)
        json_data = r.json()

        if json_data.get("errors"):
            return None
        elif json_data.get("message") and json_data.get("message") == "Bad credentials":
            logging.warning("GITHUB_TOKEN environment variable is invalid")
            return None

        return json_data["data"]["repository"]["ref"]["target"]["history"]["edges"][0]["node"]["committedDate"]
