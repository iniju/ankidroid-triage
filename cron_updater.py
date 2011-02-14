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
from google.appengine.ext import db

from receive_ankicrashes import Bug

class CronjobSettings(db.Model):
	name = db.StringProperty(required=True)
	step = db.IntegerProperty(required=True)
	offset = db.IntegerProperty(required=True)

class ScanIssues(webapp.RequestHandler):
	settings_name = 'issueScanner'
	default_step = 10
	def get(self):
		cronSettings_query = CronjobSettings.all()
		cronSettings_query.filter('name=', ScanIssues.settings_name)
		cs = None
		if cronSettings_query.count(1) == 0:
			logging.info('initializing scanner for issues')
			cs = CronjobSettings(name = ScanIssues.settings_name, step = ScanIssues.default_step, offset = 0)
			cs.put()
		else:
			cs = cronSettings_query.fetch(1)[0]

		bugs_query = Bug.all()
		bugs_query.filter('linked =', False)
		if cs.offset > bugs_query.count(1000000):
			cs_offset = 0
		bugs = []
		bugs = bugs_query.fetch(cs.step, cs.offset)
		for bg in bugs:
			issues = bg.findIssue()
			if issues:
				bg.issueName = issues[0]['id']
				logging.info("ScanIssues: Autolinking bug " + str(bg.key().id()) + " to issue " + str(bg.issueName))
				bg.put()
		cs.offset += cs.step
		cs.put()

class UpdateStatusesPriorities(webapp.RequestHandler):
	settings_name = 'statusScanner'
	default_step = 10
	def get(self):
		cronSettings_query = CronjobSettings.all()
		cronSettings_query.filter('name=', UpdateStatusesPriorities.settings_name)
		cs = None
		if cronSettings_query.count(1) == 0:
			logging.info('initializing scanner for status')
			cs = CronjobSettings(name = UpdateStatusesPriorities.settings_name, step = UpdateStatusesPriorities.default_step, offset = 0)
			cs.put()
		else:
			cs = cronSettings_query.fetch(1)[0]

		bugs_query = Bug.all()
		bugs_query.filter('linked =', True)
		if cs.offset > bugs_query.count(1000000):
			cs_offset = 0
		bugs = []
		bugs = bugs_query.fetch(cs.step, cs.offset)
		logging.debug("Cron job updater, found " + str(bugs_query.count(1000000)) + " bugs")
		for bg in bugs:
			if bg.updateStatusPriority():
				logging.debug("Updated status and/or priority for bug: '" + str(bg.key().id()) + "'")
				bg.put()
		cs.offset += cs.step
		cs.put()
		
application = webapp.WSGIApplication(
		[(r'^/cron_updater/status_priority?.*', UpdateStatusesPriorities),
		(r'^/cron_updater/issue_scanner?.*', ScanIssues)],
		debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()

