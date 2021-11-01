#!/usr/bin/env python3
import os
import sys
import requests
import json
import re
from unidiff import PatchSet
import pathlib
#  from IPython import embed


'''
TODO:
[DONE] 1. Link to project in UI
2. Get JSON for issues/vulns and put in comment
[DONE] 3. Add in error codes
    11 - couldn't get PR diff
    12 - found non-concrete dependencies
'''

class AnalyzePRForReqs():
    def __init__(self, repo, pr_num, vul, mal, eng, lic, aut):
        #  self.owner = owner
        self.repo = repo
        self.pr_num = pr_num
        self.vul = float(vul)
        self.mal = float(mal)
        self.eng = float(eng)
        self.lic = float(lic)
        self.aut = float(aut)


    def get_PR_diff(self):
        #  resp = requests.get('https://patch-diff.githubusercontent.com/raw/peterjmorgan/phylum-demo/pull/7.diff')
        repo = self.repo
        if '_' in repo:
            repo = repo.replace('_','-')
        url = f"https://patch-diff.githubusercontent.com/raw/{repo}/pull/{self.pr_num}.diff"
        try:
            resp = requests.get(url)
        except Exception as e:
            print(f"[ERROR] Couldn't get patch diff via url")
            sys.exit(11)
        print(f"[D] get_PR_diff - resp.status_code: {resp.status_code}")
        return resp.content


# get the diff hunks
    def get_reqs_hunks(self, diff_data):
        patches = PatchSet(diff_data.decode('utf-8'))

        changes = list()
        for patchfile in patches:
            # TODO: check other files
            if 'requirements.txt' in patchfile.path:
                for hunk in patchfile:
                    for line in hunk:
                        if line.is_added:
                            changes.append(line.value)
        print(f"[DEBUG] get_reqs_hunks: found {len(changes)} changes")
        return changes

    def generate_pkgver(self, changes):
        pat = re.compile(r"(.*)==(.*)")
        no_version = 0
        pkg_ver = dict()
        pkg_ver_tup = list()

        for line in changes:
            if line == '\n':
                continue
            if match := re.match(pat, line):
                pkg,ver = match.groups()
                pkg_ver[pkg] = ver
                pkg_ver_tup.append((pkg,ver))
            else:
                no_version += 1

        if no_version > 0:
            print(f"[ERROR] Found entries that do not specify version, preventing analysis. Exiting")
            sys.exit(11)

        return pkg_ver_tup

    def read_phylum_analysis(self, filename='/home/runner/phylum_analysis.json'):
        if not pathlib.Path(filename).is_file():
            print(f"[ERROR] Cannot find {filename}")
            sys.exit(11)
        with open(filename,'r') as infile:
            phylum_analysis_json = json.loads(infile.read())
        print(f"[DEBUG] read {len(phylum_analysis_json)} bytes")
        return phylum_analysis_json

    def parse_risk_data(self, phylum_json, pkg_ver):
        phylum_pkgs = phylum_json.get('packages')
        risk_scores = list()
        for pkg,ver in pkg_ver:
            for elem in phylum_pkgs:
                if elem.get('name') == pkg and elem.get('version') == ver:
                    risk_scores.append(self.check_risk_scores(elem))

        return risk_scores

    def check_risk_scores(self, package_json):
        riskvectors = package_json.get('riskVectors')
        failed = 0
        fail_string = f"### Package: `{package_json.get('name')}` failed.\n"
        fail_string += f"|Risk Domain|Identified Score|Requirement|\n"
        fail_string += f"|-----------|----------------|-----------|\n"


        pkg_vul = riskvectors.get('vulnerability')
        pkg_mal = riskvectors.get('malicious_code')
        pkg_eng = riskvectors.get('engineering')
        pkg_lic = riskvectors.get('license')
        pkg_aut = riskvectors.get('author')
        if pkg_vul < self.vul:
            failed = 1
            # fail_string += f"\t- Vulnerability Risk: identified score: **{pkg_vul}** - requirement: **{self.vul}**\n"
            fail_string += f"|Software Vulnerability|{pkg_vul}|{self.vul}|\n"
        if pkg_mal < self.mal:
            failed = 1
            # fail_string += f"\t- Malicious Code Risk: identified score: **{pkg_mal}** - requirement: **{self.mal}**\n"
            fail_string += f"|Malicious Code|{pkg_mal}|{self.mul}|\n"
        if pkg_eng < self.eng:
            failed = 1
            fail_string += f"|Engineering|{pkg_eng}|{self.eng}|\n"
        if pkg_lic < self.lic:
            failed = 1
            # fail_string += f"\t- License Risk: package risk score: {pkg_lic} - requirement: {self.lic}\n"
            fail_string += f"|License|{pkg_lic}|{self.lic}|\n"
        if pkg_aut < self.aut:
            failed = 1
            # fail_string += f"\t- Author Risk: package risk score: {pkg_aut} - requirement: {self.aut}\n"
            fail_string += f"|Author|{pkg_aut}|{self.aut}|\n"

        return fail_string if failed else None

    def get_project_url(self, phylum_json):
        project_id = phylum_json.get("project")
        url = f"https://app.phylum.io/projects/{project_id}"
        return url

    def run(self):
        diff_data = self.get_PR_diff()
        changes = self.get_reqs_hunks(diff_data)
        pkg_ver = self.generate_pkgver(changes)
        #  phylum_json = self.read_phylum_analysis()
        phylum_json = self.read_phylum_analysis('/home/runner/phylum_analysis.json')
        risk_data = self.parse_risk_data(phylum_json, pkg_ver)
        project_url = self.get_project_url(phylum_json)

        #  embed()
        for line in risk_data:
            if line:
                print(line)

        header = "## Phylum OSS Supply Chain Risk Analysis\n\n"

        with open('/home/runner/pr_comment.txt','w') as outfile:
            outfile.write(header)
            for line in risk_data:
                if line:
                    outfile.write(line)
            outfile.write(f"\n[View this project in Phylum UI]({project_url})")


if __name__ == "__main__":
    argv = sys.argv

    if argc := len(sys.argv) < 8:
        print(f"Usage: {argv[0]} DIFF_URL VUL_THRESHOLD MAL_THRESHOLD ENG_THRESHOLD LIC_THRESHOLD AUT_THRESHOLD")
        sys.exit(11)

    #  diff_url = argv[1]
    #  owner = argv[1]
    repo = argv[1]
    pr_num = argv[2]
    vul = argv[3]
    mal = argv[4]
    eng = argv[5]
    lic = argv[6]
    aut = argv[7]

    a = AnalyzePRForReqs(repo, pr_num, vul, mal, eng, lic, aut)
    a.run()

