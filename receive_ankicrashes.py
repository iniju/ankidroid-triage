# -*- coding: utf-8 -*-
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

import logging, email, re, hashlib
from datetime import datetime
from datetime import timedelta
from cgi import escape
from string import strip
from urllib import quote
from urllib import quote_plus
from quopri import decodestring
from email.header import decode_header
from google.appengine.api import mail, memcache
from google.appengine.ext import webapp
from google.appengine.ext.webapp.mail_handlers import InboundMailHandler
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext import db
from google.appengine.api.urlfetch import fetch
from google.appengine.api.urlfetch import Error

from pytz.gae import pytz
from pytz import timezone, UnknownTimeZoneError
from BeautifulSoup import BeautifulStoneSoup
from BeautifulSoup import BeautifulSoup
from Cnt import Cnt

class AppVersion(db.Model):
	name = db.StringProperty(required=True)
	lastIncident = db.DateTimeProperty(required=True, indexed=False)
	crashCount = db.IntegerProperty(required=True, indexed=False)
	activeFrom = db.DateTimeProperty(required=False)
	@classmethod
	def insert(cls, _name, _ts):
		version_query = AppVersion.all()
		version_query.filter('name =', _name.strip())
		versions = []
		versions = version_query.fetch(1)
		if versions:
			version = versions[0]
			if _ts and _ts.tzinfo == None:
				_ts = pytz.utc.localize(_ts)
			if pytz.utc.localize(version.lastIncident) < _ts:
				version.lastIncident = _ts
				logging.info("version " + version.name + " last incident: " + version.lastIncident.strftime(r"%d/%m/%Y %H:%M:%S %Z"))
			version.crashCount = version.crashCount + 1
			version.put()
		else:
			nv = AppVersion(name = _name.strip(), lastIncident = _ts, crashCount = 1)
			nv.put()
			Cnt.incr("AppVersion_counter")

class HospitalizedReport(db.Model):
	crashId = db.StringProperty(required=True)
	crashBody = db.TextProperty(required=True)
	diagnosis = db.StringProperty()
	processed = db.BooleanProperty()

class Bug(db.Model):
	issueStatusOrder = {
			'WaitingForFeedback': 0,
			'Started': 0,
			'Accepted': 0,
			'New': 0,
			'FixedInDev': 1,
			'Fixed': 2,
			'Done': 2,
			'Invalid': 3,
			'WontFix': 3,
			'Duplicate': 4
			}
	issuePriorityOrder = {
			'Critical': 0,
			'High': 1,
			'Medium': 2,
			'Low': 3
			}
	@classmethod
	def compareIssues(cls, a, b):
		# First prioritize on Status, then on priority, then on -ID
		#logging.info("Comparing " + str(a) + " " + str(b))
		#logging.info("Comparing status: " + str(cls.issueStatusOrder[a['status']]) + " " + str(cls.issueStatusOrder[b['status']]) + " " + str(cmp(cls.issueStatusOrder[a['status']], cls.issueStatusOrder[b['status']])))
		#logging.info("Comparing priority: " + str(cls.issuePriorityOrder[a['priority']]) + " " + str(cls.issuePriorityOrder[b['priority']]) + " " + str(cmp(cls.issuePriorityOrder[a['priority']], cls.issuePriorityOrder[b['priority']])))
		#logging.info("Comparing ID: " + str(cmp(-a['id'], -b['id'])))
		return cmp(cls.issueStatusOrder[a['status']], cls.issueStatusOrder[b['status']]) or cmp(cls.issuePriorityOrder[a['priority']], cls.issuePriorityOrder[b['priority']]) or cmp(-a['id'], -b['id'])
	signature = db.TextProperty(required=True, indexed=False)
	signHash = db.StringProperty()
	count = db.IntegerProperty(required=True)
	lastIncident = db.DateTimeProperty()
	linked = db.BooleanProperty(indexed=False)
	issueName = db.IntegerProperty(indexed=False)
	fixed = db.BooleanProperty(indexed=False)
	status = db.StringProperty(indexed=False)
	priority = db.StringProperty(indexed=False)
	def updateStatusPriority(self):
		url = r"http://code.google.com/feeds/issues/p/ankidroid/issues/full?id=" + str(self.issueName)
		updated = False
		try:
			result = fetch(url)
			if result.status_code == 200:
				soup = BeautifulStoneSoup(result.content)
				status = soup.find('issues:status')
				if status:
					self.status = unicode(status.string)
					updated = True
					logging.debug("Setting status to '" + self.status + "'")
				priority = soup.find(name='issues:label', text=re.compile(r"^Priority-.+$"))
				if priority:
					self.priority = re.search("^Priority-(.+)$", unicode(priority.string)).group(1)
					updated = True
					logging.debug("Setting priority to '" + self.priority + "'")
		except Error, e:
			logging.error("Error while retrieving status and priority: %s" % str(e))
		return updated
	def findIssue(self):
		# format signature for google query
		urlEncodedSignature = re.sub(r'([:=])(\S)', r'\1 \2', self.signature)
		urlEncodedSignature = re.sub(r'\$[0-9]+', r'$', urlEncodedSignature)
		urlEncodedSignature = quote_plus(urlEncodedSignature)
		logging.debug("findIssue: URL-Encoded: '" + urlEncodedSignature + "'")
		url = r"http://code.google.com/p/ankidroid/issues/list?can=1&q=" + urlEncodedSignature + r"&colspec=ID+Status+Priority"
		try:
			result = fetch(url)
			if result.status_code == 200:
				#logging.debug("Results retrieved (" + str(len(result.content)) + "): '" + str(result.content) + "'")
				soup = BeautifulSoup(result.content)
				issueID = soup.findAll('td', {'class': 'vt id col_0'})
				issueStatus = soup.findAll('td', {'class': 'vt col_1'})
				issuePriority = soup.findAll('td', {'class': 'vt col_2'})
				logging.debug("findIssue: Issue found: " + str(issueID) + " " + str(issueStatus) + " " + str(issuePriority))
				issues = []
				for i, issue in enumerate(issueID):
					issues.append({'id': long(unicode(issueID[i].a.string)), 'status':	strip(unicode(issueStatus[i].a.string)), 'priority': strip(unicode(issuePriority[i].a.string))})
				issues.sort(Bug.compareIssues)
				logging.debug("findIssue: sorted results list: " + str(issues))
				return issues
		except Error, e:
			logging.error("findIssue: Error while querying for matching issues: %s" % str(e))
			return []

class CrashReport(db.Model):
	crashId = db.StringProperty(required=True)
	report = db.TextProperty(required=True, indexed=False)
	packageName = db.StringProperty(indexed=False)
	versionName = db.StringProperty()
	crashSignature = db.TextProperty(indexed=False)
	signHash = db.StringProperty()
	crashTime = db.DateTimeProperty()
	crashTz = db.StringProperty()
	sendTime = db.DateTimeProperty(indexed=False)
	board = db.StringProperty(indexed=False)
	brand = db.StringProperty(indexed=False)
	model = db.StringProperty(indexed=False)
	product = db.StringProperty(indexed=False)
	device = db.StringProperty(indexed=False)
	display = db.StringProperty(indexed=False)
	androidOSId = db.StringProperty(indexed=False)
	androidOSVersion = db.StringProperty(indexed=False)
	availableInternalMemory = db.IntegerProperty(indexed=False)
	totalInternalMemory = db.IntegerProperty(indexed=False)
	bugKey = db.ReferenceProperty(Bug)
	entityVersion = db.IntegerProperty(default=2)
	adminOpsflag = db.IntegerProperty(default=6)
	groupId = db.StringProperty(default='')
	index = db.IntegerProperty(default=0, indexed=False)
	source = db.StringProperty(default='email', indexed=False)
	archived = db.BooleanProperty(default=False)
	def linkToBug(self, save=True):
		#bug = memcache.get(key=self.signHash)
		#if bug == None:
		results = Bug.all()
		results.filter('signHash = ', self.signHash)
		bug = results.get()
		#if bug:
			#logging.debug("Found existing bug")
			#memcache.set(key=self.signHash, value=bug, time=7200)
		if bug:
			bugkey = bug.key()
			logging.debug("Assigning to bug: %s" % bugkey)
			self.bugKey = bugkey
			if save:
				self.put()
				Cnt.incr("CrashReport_counter")
			bug.count += 1
			bug.lastIncident = self.crashTime
			bug.put()
			#memcache.set(key=self.signHash, value=bug, time=7200)
			return bug
		else:
			nb = Bug(signature = self.crashSignature, signHash = self.signHash, count = 1, lastIncident = self.crashTime, linked = False, fixed = False, status = '', priority = '')
			self.bugKey = nb.put()
			Cnt.incr("Bug_counter")
			logging.debug("Created new bug: %s" % nb.key())
			#memcache.set(key=self.signHash, value=nb, time=7200)
			if save:
				self.put()
				Cnt.incr("CrashReport_counter")
			return nb
	@classmethod
	def getCrashSignature(self, body):
		signLine1 = ''
		signLine2 = ''
		cleanbody = re.sub(r"<br></br>", "\n", body)
		cleanbody = re.sub(r"<br\s*/?>", "\n", cleanbody)
		cleanbody = re.sub(r"\xa0", " ", cleanbody, re.U)
		m1 = re.search(r"Begin Stacktrace[\s\n]*([^)]*?\))[\n\s]*at[\n\s]", cleanbody, re.M|re.U)
		if m1:
			signLine1 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m1.group(1))
			logging.debug('Sign m1: %s' % signLine1)
		m2 = re.search(r"[\n\s]*(at\scom\.(ichi2|mindprod|samskivert|tomgibara|hlidskialf)\.[^)]*?\))[\s\n]*at[\n\s]", cleanbody, re.M|re.U)
		if m2:
			signLine2 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m2.group(1))
			logging.debug('Sign m2: %s' % signLine2)
		return signLine1 + "\n" + signLine2

class Feedback(db.Model):
	groupId = db.IntegerProperty(required=True)
	sendTime = db.DateTimeProperty(required=True)
	timezone = db.StringProperty()
	type = db.StringProperty(indexed=False)
	message = db.TextProperty(indexed=False)

class HttpFeedbackReceiver(webapp.RequestHandler):
	def parseDateTime(self, dtstr):
		dt = dtstr.split('.')
		ts = datetime.strptime(dt[0], r'%Y-%m-%dT%H:%M:%S')
		return pytz.utc.localize(ts)
	def post(self):
		post_args = self.request.arguments()
		sentOn = None
		_type = self.request.get('type', '')

		if _type in ['feedback', 'error-feedback']:
			if 'reportsentutc' in post_args:
				sentOn = self.parseDateTime(self.request.get('reportsentutc', ''))
			_groupId = long(self.request.get('groupid', ''))
			if _groupId and sentOn:
				fb = Feedback(groupId = _groupId,
						sendTime = sentOn,
						timezone = self.request.get('reportsenttz', ''),
						type = _type,
						message = self.request.get('message', '0'))
				if message != 'Automatically sent':
					fb.put()
					Cnt.incr("Feedback_counter")
				self.response.out.write("OK")
			else:
				self.error(400)
		else:
			self.error(400)

class HttpCrashReceiver(webapp.RequestHandler):
	def parseDateTime(self, dtstr):
		dt = dtstr.split('.')
		ts = datetime.strptime(dt[0], r'%Y-%m-%dT%H:%M:%S')
		#micros = dt[1][:6]
		#ts = ts + timedelta(microseconds = long(micros + "000000"[len(micros):]))
		return pytz.utc.localize(ts)
	def parseEssentials(self, cr, req, signature, groupId, index):
		cr.packageName = req.get('packagename', '')
		cr.versionName = req.get('versionname', '').strip()
		cr.crashSignature = signature
		cr.signHash = hashlib.sha1(signature).hexdigest()
		cr.sendTime = self.parseDateTime(req.get('reportsentutc', ''))
		cr.crashTz = req.get('reportgeneratedtz', '')
		cr.crashTime = self.parseDateTime(req.get('reportgeneratedutc', ''))
		cr.board = req.get('board', '')
		cr.brand = req.get('brand', '')
		cr.model = req.get('model', '')
		cr.display = req.get('display', '')
		cr.product = req.get('product', '')
		cr.device = req.get('device', '')
		cr.androidOSId = req.get('id', '')
		cr.androidOSVersion = req.get('androidversion', '')
		cr.availableInternalMemory = long(req.get('availableinternalmemory', '0'))
		cr.totalInternalMemory = long(req.get('totalinternalmemory', '0'))
		cr.groupId = groupId
		cr.index = index
		cr.source = "http"
	def post(self):
		post_args = self.request.arguments()
		_type = self.request.get('type', '')

		for name in post_args:
			try:
				logging.debug('pair: %s = "%s"' % (name, self.request.get(name)))
			except:
				pass
		if _type in ['crash-stacktrace']:
			_groupId = self.request.get('groupid', '')
			try:
				_index = long(self.request.get('index', ''))
			except ValueError:
				_index = -1
			if _groupId and _index >= 0:
				body = self.request.get('stacktrace', '')
				if body:
					signature = CrashReport.getCrashSignature(body)
					sendTime = self.parseDateTime(self.request.get('reportsentutc', ''))
					sendtz = self.request.get('reportsenttz', '')
					if signature != "\n" and sendTime and sendtz:
						tz = timezone(sendtz)
						logging.debug("ts: " + sendTime.astimezone(tz).strftime("%a %b %d %H:%M:%S %%s %Y"))
						_crashId = 'HTTP Bug Report on %s num: %03d' % (sendTime.astimezone(tz).strftime("%a %b %d %H:%M:%S %%s %Y"), _index)
						_crashId = _crashId % sendtz
						logging.debug("HTTP report: " + _crashId)
						cr = CrashReport(crashId = _crashId, report = body)
						self.parseEssentials(cr, self.request, signature, _groupId, _index)
						if cr.versionName != '':
							# Check for duplicates
							dupl_query = CrashReport.all()
							dupl_query.filter('crashTime =', cr.crashTime)
							dupl_query.filter('signHash =', cr.signHash)
							if dupl_query.count(1) == 0:
								bug = cr.linkToBug(True)
								AppVersion.insert(cr.versionName, cr.crashTime)
								if bug.count == 1:
									self.response.out.write("new")
								else:
									issueName = bug.issueName
									if issueName is None:
										self.response.out.write("known")
									else:
										self.response.out.write("issue:%d:%s" % (bug.issueName, bug.status))
								logging.info("New crash: %d" % cr.key().id())
							else:
								logging.error("HttpCrashReceiver: duplicate crash report")
								self.error(400)
						else:
							logging.error("HttpCrashReceiver: cannot extract versionName")
							self.error(400)
					else:
						logging.error("HttpCrashReceiver: cannot extract signature")
						self.error(400)
				else:
					logging.error("HttpCrashReceiver: stacktrace (" + body + ") not available")
					self.error(400)
			else:
				logging.error("HttpCrashReceiver: groupid (%s) or id (%s) are not available", _groupId, self.request.get('index', ''))
				self.error(400)
		else:
			logging.error("HttpCrashReceiver: wrong tpost type (" + _type + ")")
			self.error(400)

def main():
	application = webapp.WSGIApplication([#LogSenderHandler.mapping(),
		(r'^/crash_receiver/?.*', HttpCrashReceiver),
		(r'^/feedback_receiver/?.*', HttpFeedbackReceiver)], debug=True)
	run_wsgi_app(application)

if __name__ == '__main__':
	main()

