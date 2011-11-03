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

from google.appengine.ext import webapp
from google.appengine.api import memcache
from google.appengine.ext.webapp.util import run_wsgi_app

from receive_ankicrashes import AppVersion
from receive_ankicrashes import CrashReport
from receive_ankicrashes import HospitalizedReport
from receive_ankicrashes import Bug

from google.appengine.api import logservice
logservice.AUTOFLUSH_ENABLED = False

class BackendTest(webapp.RequestHandler):
	def rebuild_signatures(self):
		#memcache.incr('backend_status')
		#crashes_query = CrashReport.all()
		#total_crashes = crashes_query.count(1000000)
		#logging.info('Total crashes: %d' % total_crashes)
		#logservice.flush()
		#memcache.incr('backend_status')
		#crashes_query = CrashReport.all()
		#crashes_query.filter('adminOpsflag =', 0)
		#unprocessed_crashes = crashes_query.count(1000000)
		#logging.info('Unprocessed crashes: %d' % unprocessed_crashes)
		#logservice.flush()
		#memcache.incr('backend_status')
		#processed_crashes = 0
		while(True):
			crashes_query = CrashReport.all()
			crashes_query.filter('adminOpsflag =', 0)
			crashes = crashes_query.fetch(100)
			if crashes:
				for cr in crashes:
					signature = CrashReport.getCrashSignature(cr.report)
					cr.crashSignature = signature
					cr.signHash = hashlib.sha1(signature).hexdigest()
					cr.adminOpsflag = 1
					cr.put()
					#processed_crashes+=1
			else:
				break
			#memcache.set(key='backend_status', value=100.0*processed_crashes/unprocessed_crashes, time=900)
			break

	def rebuild_bugs(self):
		#memcache.incr('backend_status')
		#crashes_query = CrashReport.all()
		#total_crashes = crashes_query.count(1000000)
		#logging.info('Total crashes: %d' % total_crashes)
		#logservice.flush()
		#memcache.incr('backend_status')
		#crashes_query = CrashReport.all()
		#crashes_query.filter('adminOpsflag =', 0)
		#unprocessed_crashes = crashes_query.count(1000000)
		#logging.info('Unprocessed crashes: %d' % unprocessed_crashes)
		#logservice.flush()
		#memcache.incr('backend_status')
		#processed_crashes = 0
		while(True):
			crashes_query = CrashReport.all()
			crashes_query.filter('adminOpsflag =', 1)
			crashes_query.order('signHash')
			crashes = crashes_query.fetch(500)
			if crashes:
				for cr in crashes:
					cr.adminOpsflag = 5
					cr.linkToBug()
#					signature = CrashReport.getCrashSignature(cr.report)
#					cr.crashSignature = signature
#					cr.signHash = hashlib.sha1(signature).hexdigest()
#					cr.adminOpsflag = 1
#					cr.put()
					#processed_crashes+=1
			else:
				break
			#memcache.set(key='backend_status', value=100.0*processed_crashes/unprocessed_crashes, time=900)
			break

	def get(self):
		cmd = self.request.get('cmd')
		op = self.request.get('op')
		if cmd == 'Clear':
			memcache.delete('backend_name')
			memcache.delete('backend_status')
			logging.info("Stopping backend with command: " + op)
			logservice.flush()
		else:
			backend_status = memcache.get('backend_status')
			if backend_status == None:
				memcache.set(key='backend_status', value=0, time=900)
				memcache.set(key='backend_name', value=op, time=900)
				logging.info("Backend(%s) started" % op)
				logservice.flush()
				if op == "rebuild_signatures":
					self.rebuild_signatures()
				elif op == "rebuild_bugs":
					self.rebuild_bugs()
				memcache.delete('backend_status')
				logging.info("Backend(%s) completed" % op)
				logservice.flush()
			else:
				logging.info('Backend already running')
				logservice.flush()
			time.sleep(60)
		
application = webapp.WSGIApplication(
		[(r'^/backend/testing.*$', BackendTest)],
		debug=True)

if __name__ == "__main__":
	run_wsgi_app(application)

