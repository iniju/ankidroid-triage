# ###
# Copyright (c) 2010 Konstantinos Spyropoulos <inigo.aldana@gmail.com>
#
# This file is part of ankidroid-triage
#
# ankidroid-triage is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# ankidroid-triage is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
# without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with ankidroid-triage.
# If not, see http://www.gnu.org/licenses/.
# #####
import os, logging, re
from operator import attrgetter
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from google.appengine.dist import use_library
use_library('django', '1.1')
# Force Django to reload its settings.
from django.conf import settings
settings._target = None

from google.appengine.ext import webapp
from google.appengine.api import memcache
from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from google.appengine.api.urlfetch import fetch
from google.appengine.api.urlfetch import Error
from google.appengine.ext.webapp import blobstore_handlers

from receive_ankicrashes import AppVersion
from receive_ankicrashes import CrashReport
from receive_ankicrashes import Bug
from Cnt import Cnt
from Lst import Lst
from FileWr import FileWr

webapp.template.register_template_library('templatetags.basic_math')

class MainPage(webapp.RequestHandler):
	def get(self):
		self.redirect("/report_crashes/")

class ViewBug(webapp.RequestHandler):
	def post(self):
		post_args = self.request.arguments()
		bugId = self.request.get('bug_id')
		bug = Bug.get_by_id(long(bugId))
		issues = []
		if bug:
			if "find_issue" in post_args:
				# Scan for matching issue
				issues = bug.findIssue()
			elif "save_issue" in post_args:
				# Save the entered issue
				issueName = self.request.get('issue')
				if re.search(r"^[0-9]*$", issueName):
					if issueName:
						bug.issueName = long(issueName)
						bug.linked = True
						bug.updateStatusPriority()
					else:
						bug.issueName = None
						bug.linked = False
						bug.status = ''
						bug.priority = ''
					bug.fixed = False
					bug.put()
					logging.debug("Saving issue - value: '" + issueName + "'")
				else:
					logging.warning("Saving issue - non numeric value: '" + issueName + "'")
		else:
			logging.warning("Saving issue - not valid bug ID: '" + bugId + "'")
		single_result = ''
		if len(issues) == 1:
			single_result = issues[0]['id']
		template_values = {'bg': bug, 'issues': issues, 'single_result': single_result}
		path = os.path.join(os.path.dirname(__file__), 'templates/bug_view.html')
		self.response.out.write(template.render(path, template_values))

	def get(self):
		bugId = self.request.get('bug_id')
		bug = Bug.get_by_id(long(bugId))
		template_values = {'bg': bug}
		path = os.path.join(os.path.dirname(__file__), 'templates/bug_view.html')
		self.response.out.write(template.render(path, template_values))

class ViewCrash(webapp.RequestHandler):
	def get(self):
		crId = self.request.get('crash_id')
		crash = CrashReport.get_by_id(long(crId))
		template_values = {'cr': crash}
		path = os.path.join(os.path.dirname(__file__), 'templates/crash_view.html')
		self.response.out.write(template.render(path, template_values))


class ReportBugs(webapp.RequestHandler):
	def get(self):
		#versions_query = AppVersion.all()
		#versions_query.order("-activeFrom")
		#versions_objs = versions_query.fetch(2000)
		#versions = [v.name for v in versions_objs]
		#versions.insert(0, "all")
		versions = Lst.get('all_version_names_list')
		selectedVersion = self.request.get('filter_version', "all")

		bugs = []
		page = int(self.request.get('page', 0))
		if selectedVersion != "all":
			crashes = []
			bugs_map = {}
			crashes_query = CrashReport.all()
			crashes_query.filter("versionName =", selectedVersion)
			crashes = crashes_query.fetch(1000000)
			for cr in crashes:
				if cr.bugKey.key().id() in bugs_map:
					bugs_map[cr.bugKey.key().id()].count += 1
					if bugs_map[cr.bugKey.key().id()].lastIncident < cr.crashTime:
						bugs_map[cr.bugKey.key().id()].lastIncident = cr.crashTime
				else:
					bug = cr.bugKey
					bug.count = 1
					bug.lastIncident = cr.crashTime
					bugs_map[cr.bugKey.key().id()] = bug
			unsorted_bugs = bugs_map.values()
			bugs = sorted(unsorted_bugs, key=attrgetter('count'), reverse=True)
			total_results = len(bugs)
			last_page = max((total_results - 1) // 20, 0)
			if page > last_page:
				page = last_page
			# trim results to a single page
			bugs[(page+1)*20:] = []
			bugs[0:page*20] = []
		else:
			bugs_query = Bug.all()
			bugs_query.order("-count")
			total_results = bugs_query.count(1000000)
			#total_results = Cnt.get("Bug_counter")
			last_page = max((total_results - 1) // 20, 0)
			if page > last_page:
				page = last_page
			bugs = bugs_query.fetch(20, int(page)*20)

		template_values = {'bugs_list': bugs,
				'versions_list': versions,
				'filter_version': selectedVersion,
				'total_results': total_results,
				'page_size': 20,
				'page': page,
				'last_page': last_page}

		path = os.path.join(os.path.dirname(__file__), 'templates/bug_list.html')
		self.response.out.write(template.render(path, template_values))


class CrashExportServer(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self):
		fw = FileWr.get_by_key_name("crash_export_csv")
		self.send_blob(fw.bkey)
class BugExportServer(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self):
		fw = FileWr.get_by_key_name("bug_export_csv")
		self.send_blob(fw.bkey)
class FeedbackExportServer(blobstore_handlers.BlobstoreDownloadHandler):
	def get(self):
		fw = FileWr.get_by_key_name("feedback_export_csv")
		self.send_blob(fw.bkey)

class ExportCrashes(webapp.RequestHandler):
	def get(self):
		crashes_query = CrashReport.all()
		bugId = self.request.get('bug_id')

		cacheId = "CrashReport"
		crashes_query.order("-crashTime")
		crashes = []
		if bugId:
			bug = Bug.get_by_id(long(bugId))
			crashes_query.filter("bugKey =", bug)
			cacheId += bugId
		cacheId += "_counter"
		crashes_query.order("-crashTime")
		total_results = memcache.get(cacheId)
		if total_results is None:
			total_results = Cnt.get(cacheId)
			if total_results is None:
				total_results = crashes_query.count(1000000)
				memcache.set(cacheId, total_results, 432000)

		crashes = crashes_query.fetch(1000000)
		template_values = {'crashes_list': crashes,
				'total_results': total_results,
				'bug_id': bugId}
		path = os.path.join(os.path.dirname(__file__), 'templates/crash_list.csv')
		self.response.out.write(template.render(path, template_values))


class ReportCrashes(webapp.RequestHandler):
	def get(self):
		versions = Lst.get('all_version_names_list')

		crashes_query = CrashReport.all()
		bugId = self.request.get('bug_id')
		page = int(self.request.get('page', 0))
		selectedVersion = self.request.get('filter_version', "all")
		logging.info("version: " + selectedVersion)

		crashes = []
		cacheId = "CrashReport"
		if bugId:
			bug = Bug.get_by_id(long(bugId))
			crashes_query.filter("bugKey =", bug)
			cacheId += bugId
		if selectedVersion != "all":
			crashes_query.filter("versionName =", selectedVersion)
			cacheId += selectedVersion
		cacheId += "_counter"
		crashes_query.order("-crashTime")
		total_results = memcache.get(cacheId)
		if total_results is None:
			total_results = Cnt.get(cacheId)
			if total_results is None:
				total_results = crashes_query.count(1000000)
				memcache.set(cacheId, total_results, 432000)
		last_page = max((total_results - 1) // 20, 0)

		if page > last_page:
			page = last_page
		crashes = crashes_query.fetch(20, int(page)*20)
		template_values = {'crashes_list': crashes,
				'versions_list': versions,
				'filter_version': selectedVersion,
				'total_results': total_results,
				'page_size': 20,
				'page': page,
				'last_page': last_page,
				'bug_id': bugId}
		path = os.path.join(os.path.dirname(__file__), 'templates/crash_list.html')
		self.response.out.write(template.render(path, template_values))

application = webapp.WSGIApplication(
		[(r'^/?$', MainPage),
			(r'^/report_crashes/?.*', ReportCrashes),
			(r'^/report_bugs/?.*', ReportBugs),
			(r'^/view_crash/?.*', ViewCrash),
			(r'^/view_bug/?.*', ViewBug),
			(r'^/export_crash.csv/?.*', CrashExportServer),
			(r'^/export_bug.csv/?.*', BugExportServer),
			(r'^/export_feedback.csv/?.*', FeedbackExportServer)],
		debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()

