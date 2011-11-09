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

import os, sys, logging, re, hashlib, time
from datetime import datetime
from urllib import quote_plus
from string import strip
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

from google.appengine.dist import use_library
use_library('django', '1.1')
# Force Django to reload its settings.
from django.conf import settings
settings._target = None

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from google.appengine.api.urlfetch import fetch
from google.appengine.api.urlfetch import Error
from google.appengine.api import taskqueue
from google.appengine.api import memcache

from receive_ankicrashes import AppVersion
from receive_ankicrashes import Feedback
from receive_ankicrashes import CrashReport
from receive_ankicrashes import HospitalizedReport
from receive_ankicrashes import Bug
from BeautifulSoup import BeautifulSoup
from Cnt import Cnt

# Remove the standard version of Django
#for k in [k for k in sys.modules if k.startswith('django')]:
#	del sys.modules[k]
webapp.template.register_template_library('templatetags.basic_math')

class AdminOpsBackendManager(webapp.RequestHandler):
	def get(self):
		#q = CrashReport.all(keys_only=True)
		#Cnt.set("CrashReport_counter", q.count(1000000))
		
		#q = Feedback.all(keys_only=True)
		#Cnt.set("Feedback_counter", q.count(1000000))

		#q = Bug.all(keys_only=True)
		#Cnt.set("Bug_counter", q.count(1000000))

		#q = AppVersion.all(keys_only=True)
		#Cnt.set("AppVersion_counter", q.count(1000000))

		outputstr = "CrashReport_counter: %d<br>Feedback_counter: %d<br>Bug_counter: %d<br>AppVersion_counter: %d" % (Cnt.get("CrashReport_counter"), Cnt.get("Feedback_counter"), Cnt.get("Bug_counter"), Cnt.get("AppVersion_counter"))
		self.response.out.write(outputstr)

	def post(self):
		params = {'op': self.request.get('op'), 'cmd': self.request.get('cmd')}
		#taskqueue.add(queue_name='admin-ops-queue', url='/backend/testing', params=params, method='GET', target='admin-ops-handler')
		for i in range(1, 98):
			taskqueue.add(queue_name='admin-ops-queue', url='/backend/testing', params=params, method='GET')#, target='admin-ops-handler')

		#time.sleep(5)
		#self.redirect('/admin_ops/backend')

class ShowCrashBody(webapp.RequestHandler):
	def get(self):
		crId = long(self.request.get('id'))
		cr = CrashReport.get_by_id(crId)
		m = re.search(r'^(.*--\&gt; END REPORT 1 \&lt;--).*$', cr.report, re.S)
		new_report = m.group(1)
		template_values = {'crash_body': cr.report, 'new_crash_body': new_report}
		logging.info(cr.report)
		logging.info(new_report)
		path = os.path.join(os.path.dirname(__file__), 'templates/admin_ops_show.html')
		self.response.out.write(template.render(path, template_values))

###
# This class is used for bulk ad hoc operations in the DB, eg reparsing signatures, rebuilding the
# bugs table or adding new properties to the entities.
#
# Due to limitations of time and memory in the AppEngine, we can't process all the entities in a
# big loop, we have to work in batches. Each page loaded is a batch, following Next we can process
# the next one, until all are done.
##########
class RebuildVersions(webapp.RequestHandler):
	batch_size = 400
	def get(self):
		batch = RebuildVersions.batch_size
		crashes_query = CrashReport.all()
		crashes = []
		page = int(self.request.get('page', 0))
		if page == 0:
			# Reset appVersion crashCount & lastIncident
			versions_query = AppVersion.all()
			versions = versions_query.fetch(2000)
			for v in versions:
				v.crashCount = 0
				v.lastIncident = datetime(2000,1,1)
				v.put()

		total_results = crashes_query.count(1000000)
		logging.info("Admin ops - total_results: ", total_results)
		last_page = max((total_results - 1) // batch, 0)
		if page > last_page:
			page = last_page
		crashes = crashes_query.fetch(batch, page * batch)
		versionCounts = {}
		versionLastIncidents = {}
		for cr in crashes:
			vname = cr.versionName.strip()
			if cr.versionName <> vname:
				cr.versionName = vname
				cr.put()
			if vname in versionCounts:
				versionCounts[vname] = versionCounts[vname] + 1
			else:
				versionCounts[vname] = 1

			if cr.versionName in versionLastIncidents:
				if versionLastIncidents[vname] < cr.crashTime:
					versionLastIncidents[vname] = cr.crashTime
			else:
				versionLastIncidents[vname] = cr.crashTime

		for vname in versionCounts:
			versions_query = AppVersion.all()
			versions_query.filter('name =', vname)
			versions = versions_query.fetch(1)
			if versions:
				version = versions[0]
				version.crashCount = version.crashCount + versionCounts[vname]
				if version.lastIncident < versionLastIncidents[vname]:
					version.lastIncident = versionLastIncidents[vname]
				version.put()
			else:
				logging.info("missing version: " + vname)

		template_values = {
				'values': versionCounts,
				'page': page,
				'last_page': last_page,
				'page_size': batch,
				'op_link': 'rebuild_versions',
				'column_key': 'Version',
				'column_value': 'Count',
				'page_results': len(crashes),
				'total_results': total_results}
		path = os.path.join(os.path.dirname(__file__), 'templates/admin_ops.html')
		self.response.out.write(template.render(path, template_values))

class RebuildBugs(webapp.RequestHandler):
	def get(self):
		batch = RebuildBugs.batch_size
		crashes_query = CrashReport.all()
		crashes = []
		page = int(self.request.get('page', 0))
		if page == 0:
			# Remove Bugs
			bugs_query = Bug.all()
			bugs = bugs_query.fetch(2000)
			for b in bugs:
				b.delete()

		total_results = crashes_query.count(1000000)
		last_page = max((total_results - 1) // batch, 0)
		if page > last_page:
			page = last_page
		logging.info("Admin ops - total_results: ", str(total_results) + ", page: " + str(page) + "/" + str(last_page))
		crashes = crashes_query.fetch(batch, page * batch)
		valueSet = {}
		valueSet["unlinked"] = 0
		# Main ops loop
		for cr in crashes:
			cr.bugKey = None
			cr.crashSignature = CrashReport.getCrashSignature(cr.report)
			cr.put()
			if cr.crashSignature == '\n':
				logging.warning("Can't get signature for CrashReport: " + str(cr.key().id()))
				valueSet["unlinked"] = valueSet["unlinked"] + 1
			else:
				cr.signHash = hashlib.sha1(cr.crashSignature).hexdigest()
				cr.linkToBug()
				bugId = str(cr.bugKey.key().id())
				if bugId in valueSet:
					valueSet[bugId] = valueSet[bugId] + 1
				else:
					valueSet[bugId] = 1
		template_values = {
				'values': valueSet,
				'page': page,
				'last_page': last_page,
				'page_size': batch,
				'op_link': 'rebuild_bugs',
				'column_key': 'BugId',
				'column_value': 'Count',
				'page_results': len(crashes),
				'total_results': total_results}
		path = os.path.join(os.path.dirname(__file__), 'templates/admin_ops.html')
		self.response.out.write(template.render(path, template_values))

application = webapp.WSGIApplication(
		[(r'^/admin_show.*$', ShowCrashBody),
		(r'^/admin_ops/rebuild_versions$', RebuildVersions),
		#(r'^/admin_ops/rebuild_bugs$', RebuildBugs)],
		(r'^/admin_ops/backend.*$', AdminOpsBackendManager)],
		debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()

