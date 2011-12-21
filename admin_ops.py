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
from __future__ import with_statement

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
from google.appengine.ext import db
from google.appengine.ext import blobstore
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template
from google.appengine.api.urlfetch import fetch
from google.appengine.api.urlfetch import Error
from google.appengine.api import taskqueue
from google.appengine.api import memcache
from google.appengine.api import files
from google.appengine.ext.webapp import blobstore_handlers

from receive_ankicrashes import AppVersion
from receive_ankicrashes import Feedback
from receive_ankicrashes import CrashReport
from receive_ankicrashes import Bug
from BeautifulSoup import BeautifulSoup
from Cnt import Cnt
from FileWr import FileWr
from Lst import Lst

webapp.template.register_template_library('templatetags.basic_math')

class BlobSetter(webapp.RequestHandler):
	def get(self):
		fwe = FileWr.get_by_key_name("export_csv")
		fwc = FileWr(key_name="crash_export_csv")
		fwc.bkey = fwe.bkey
		fwc.put()
		self.response.out.write("OK")

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

application = webapp.WSGIApplication(
		[(r'^/admin_show.*$', ShowCrashBody),
		(r'^/admin_ops/bset.*$', BlobSetter)],
		debug=True)

def main():
	run_wsgi_app(application)

if __name__ == "__main__":
	main()

