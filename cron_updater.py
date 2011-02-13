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

from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app

from receive_ankicrashes import Bug

class ScanIssues(webapp.RequestHandler):
	def get(self):
		bugs_query = Bug.all()
		bugs_query.filter('linked =', False)
		bugs = []
		bugs = bugs_query.fetch(1000)
		for bg in bugs:
			issues = bg.findIssue()
			if issues:
				bg.issueName = issues[0]['id']
				logging.info("ScanIssues: Autolinking bug " + str(bg.key().id()) + " to issue " + str(bg.issueName))
				bg.put()

class UpdateStatusesPriorities(webapp.RequestHandler):
	def get(self):
		bugs_query = Bug.all()
		#bugs_query.filter('issueName !=', None)
		bugs_query.filter('linked =', True)
		bugs = []
		bugs = bugs_query.fetch(1000)
		logging.debug("Cron job updater, found " + str(bugs_query.count(1000000)) + " bugs")
		for bg in bugs:
			if bg.updateStatusPriority():
				logging.debug("Updated status and/or priority for bug: '" + str(bg.key().id()) + "'")
				bg.put()
		
application = webapp.WSGIApplication(
		[(r'^/cron_updater/status_priority?.*', UpdateStatusesPriorities),
		(r'^/cron_updater/issue_scanner?.*', ScanIssues)],
		debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()

