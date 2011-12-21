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

import logging

from google.appengine.ext import webapp
from google.appengine.api import taskqueue
from google.appengine.ext.webapp.util import run_wsgi_app

from FileWr import FileWr

from google.appengine.api import logservice
logservice.AUTOFLUSH_ENABLED = False

class BackendExportBuilder(webapp.RequestHandler):
	def get(self):
		self.append2Csv('crash-export-queue', 'crash_export_csv', 'crash_export.csv', u'CrashId\tCrashTime\tTimeZone\tVersion\tAndroidVersion\tBrand\tModel\tProduct\tDevice\tAvailableMem\tGroupId\tOrigin\tBugId\n')
		self.append2Csv('bug-export-queue', 'bug_export_csv', 'bug_export.csv', u'BugId\tSignature\n')
		self.append2Csv('feedback-export-queue', 'feedback_export_csv', 'feedback_export.csv', u'GroupId\tType\tsendTime\tTimeZone\tMessage\n')
	def append2Csv(self, queueName, fileName, blobName, header):
		q = taskqueue.Queue(queueName)
		data = ''
		count = 0
		tasks = q.lease_tasks(600, 1000)
		for t in tasks:
			payload = t.payload
			data += payload + '\n'
			count += 1
		logging.info("%s: %d items, %d bytes" % (queueName, count, len(data)))
		fw = FileWr.get_by_key_name(fileName)
		if not fw:
			fw = FileWr(key_name=fileName)
			fw.append(blobName, header)
		fw.append(blobName, data)
		q.delete_tasks(tasks)
	
application = webapp.WSGIApplication(
		[(r'^/backend/append_export.*$', BackendExportBuilder)],
		debug=True)

if __name__ == "__main__":
	run_wsgi_app(application)

