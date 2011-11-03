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
		#results = db.GqlQuery("SELECT * FROM Bug WHERE signHash = :1", self.signHash)
		bug = results.get()
		#if bug:
			#logging.debug("Found existing bug")
			#memcache.set(key=self.signHash, value=bug, time=7200)
		if bug:
			bugkey = bug.key()
		#	if self.bugKey != bugkey:
			logging.debug("Assigning to bug: %s" % bugkey)
			#oldbug = self.bugKey
			self.bugKey = bugkey
			if save:
				self.put()
			bug.count += 1
			bug.lastIncident = self.crashTime
			bug.put()
			#memcache.set(key=self.signHash, value=bug, time=7200)
				#if oldbug:
			#		logging.debug("Reducing count (%d) of old bug: %d" % oldbug.count, oldbug.key().id())
			#		if oldbug.count == 1:
			#			#logging.debug("Deleting old bug: %d" % oldbug.key().id())
			#			oldbug.delete()
			#		else:
			#			#logging.debug("Old bug count: %d" % oldbug.count)
			#			oldbug.count -= 1
			#			oldbug.put()
			#else:
			#	logging.debug("Same as old bug: %d" % oldbug.key().id())
		else:
			logging.debug("Created new bug")
			nb = Bug(signature = self.crashSignature, signHash = self.signHash, count = 1, lastIncident = self.crashTime, linked = False, fixed = False, status = '', priority = '')
			self.bugKey = nb.put()
			#memcache.set(key=self.signHash, value=nb, time=7200)
			#logging.debug("Linked to bug, new count: " + str(self.bugKey.count))
			if save:
				self.put()
	@classmethod
	def parseUTCDateTime(cls, dt_str):
		m = re.match(r"(\w+ \w+ \d+ \d+:\d+:\d+ )(\S.*\S)( \d+)",  dt_str, re.U)
		if m is None:
			logging.warning("Datetime has unknown format: '" + dt_str + "' " + repr(dt_str))
			return (None, "format_unknown")
		try:
			tm = datetime.strptime(m.group(1) + m.group(3), r"%a %b %d %H:%M:%S %Y")
		except ValueError:
			logging.warning("Can't parse datetime from: '" + m.group(1) + m.group(3) + "'")
			return (None, "parsing_failed")
		try:
			tzname = m.group(2)
			tz = timezone(tzname)
		except UnknownTimeZoneError:
			# Alternative timezone formats
			newtzname = re.sub(r"^GMT\+03:30$", r"Asia/Tehran", tzname)
			newtzname = re.sub(r"^(\w+[+-])0?(\d*)[:.]00$", r"\1\2", newtzname)
			newtzname = re.sub(r"^(GMT[+-]\d*)$", r"Etc/\1", newtzname)
			newtzname = re.sub(r"^GMT$", r"Etc/GMT+0", newtzname)
			newtzname = re.sub(r"^(EDT)$", r"EST5\1", newtzname)
			newtzname = re.sub(r"^(CDT)$", r"CST6\1", newtzname)
			newtzname = re.sub(r"^(MDT)$", r"MST7\1", newtzname)
			newtzname = re.sub(r"^(PDT)$", r"PST8\1", newtzname)
			newtzname = re.sub(r"^PST$", r"Etc/GMT-8", newtzname)
			newtzname = re.sub(r"^CST$", r"Etc/GMT-6", newtzname)
			newtzname = re.sub(r"^JST$", r"Japan", newtzname)
			newtzname = re.sub(r"^MEZ$", r"CET", newtzname)
			newtzname = re.sub(r"^CEST$", r"CET", newtzname)
			newtzname = re.sub(r"^HAEC$", r"CET", newtzname)
			newtzname = re.sub(r"^HNEC$", r"CET", newtzname)
			newtzname = re.sub(r"^AKST$", r"US/Alaska", newtzname)
			newtzname = re.sub(r"^MESZ$", r"Europe/Berlin", newtzname)
			newtzname = re.sub(r"^AWST$", r"Australia/Perth", newtzname)
			newtzname = re.sub(r"^ACDT$", r"Australia/Adelaide", newtzname)
			newtzname = re.sub(r"^AEDT$", r"Australia/Sydney", newtzname)
			newtzname = re.sub(r"^AEST$", r"Australia/Brisbane", newtzname)
			newtzname = re.sub(r"^NZDT$", r"Pacific/Auckland", newtzname)
			newtzname = re.sub(r"^CAT$", r"Etc/GMT+2", newtzname)
			newtzname = re.sub(r"^SAST$", r"Africa/Johannesburg", newtzname)
			newtzname = re.sub(r"^BRT$", r"America/Recife", newtzname)
			# See if timezone is Quoted-Printable UTF-8
			logging.debug(str(ord(newtzname[0])) +' ' + str(ord(newtzname[1])) + ' ' + str(len(newtzname)) + ' ' + repr(newtzname))
			if re.search('^[=A-Fa-f0-9 ]a$', newtzname):
				logging.debug("Trying for Quoted-Printable UTF-8 string for timezone")
				newtzname = decodestring(newtzname).decode('utf-8')
			if newtzname == u'\u041c\u043e\u0441\u043a\u043e\u0432\u0441\u043a\u043e\u0435 \u043b\u0435\u0442\u043d\u0435\u0435 \u0432\u0440\u0435\u043c\u044f':
				newtzname = "Europe/Moscow"
			logging.debug("Changed timezone from '" + tzname + "' to '" + newtzname + "'")
			try:
				tz = timezone(newtzname)
			except UnknownTimeZoneError:
				logging.warning("Unknown timezone: '" + tzname + "'")
				return (None, "timezone_unknown", "")
		try:
			tm = tz.localize(tm)
		except (ValueError, NonExistentTimeError):
			logging.warning("Error while localizing datetime '" + tm.strftime(r"%d/%m/%Y %H:%M:%S") + "' to '" + tz.zone + "'")
			return (None, "localizing_failed", "")
		logging.debug("UTC time parsed: '" + tm.astimezone(pytz.utc).strftime(r"%d/%m/%Y %H:%M:%S %Z") + "'")
		return (tm.astimezone(pytz.utc), "", tzname)
	@classmethod
	def getCrashSignature(self, body):
		signLine1 = ''
		signLine2 = ''
		cleanbody = re.sub(r"<br></br>", "\n", body)
		cleanbody = re.sub(r"<br\s*/?>", "\n", cleanbody)
		cleanbody = re.sub(r"\xa0", " ", cleanbody, re.U)
		#m1 = re.search(r"Begin Stacktrace[\s\n]*([^<\s][^<\n]*[^<\s][\s\n]*at\s[^<\n]*)", body, re.M|re.U)
		#		Begin Stacktrace\s*(\n\s*)*([^<\s][^<\n]*[^<\s]\s*\n\s*at\s[^<\n]*)", body, re.M|re.U)
		#m1 = re.search(r"Begin Stacktrace[\s\n]*([^\n]*\n\s*at[^\n]*[^\s])\s*\n", body, re.M|re.U)
		m1 = re.search(r"Begin Stacktrace[\s\n]*([^)]*?\))[\n\s]*at[\n\s]", cleanbody, re.M|re.U)
		if m1:
			signLine1 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m1.group(1))
			logging.debug('Sign m1: %s' % signLine1)
		#m2 = re.search(r"\n\s*(at\scom\.(ichi2|mindprod|samskivert|tomgibara|hlidskialf)\.[^\n]*[^\s])\s*\n", body, re.M|re.U)
		m2 = re.search(r"[\n\s]*(at\scom\.(ichi2|mindprod|samskivert|tomgibara|hlidskialf)\.[^)]*?\))[\s\n]*at[\n\s]", cleanbody, re.M|re.U)
		if m2:
			signLine2 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m2.group(1))
			logging.debug('Sign m2: %s' % signLine2)
		return signLine1 + "\n" + signLine2
#	def getCrashSignature(cls, body):
#		signLine1 = ''
#		signLine2 = ''
#		m1 = re.search(r"Begin Stacktrace\s*(<br>\s*)*([^<\s][^<]*[^<\s])\s*<br>", body, re.M|re.U)
#		if m1:
#			signLine1 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m1.group(2))
#			#signLine1 = m1.group(2)
#		m2 = re.search(r"<br>\s*(at\scom\.(ichi2|mindprod|samskivert|tomgibara)\.[^<]*[^<\s])\s*<br>", body, re.M|re.U)
#		if m2:
#			signLine2 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m2.group(1))
#			#signLine2 = m2.group(1)
#		return signLine1 + "\n" + signLine2
	#m = re.search(r".*<br>\s*(.*?com\.ichi2\.anki\..*?)<br>", body, re.M|re.U)
		#if m and m.groups():
	#		return re.sub(r"\$[a-fA-F0-9@]*", "", m.group(1))
		#return ""
	@classmethod
	def parseSimpleValue(cls, body, key, op=" = "):
		pattern = r"<br>\s*" + key + op + r"(<a>)?(.*?)(</a>)?<br>"
		m = re.search(pattern, body, re.M|re.U)
		if m and m.groups():
			logging.debug("Parsed value for key: '" + key + "' = '" + m.group(2) + "'")
			return m.group(2)
		else:
			logging.debug("Parsed nothing for key: '" + key +"'")
		return ""
	@classmethod
	def getMessageEssentials(cls, subject, body):
		m = re.search("(\[[^\]]*\])?\s*Bug Report on (.*)$", subject)
		if (m is None) or m.groups() is None:
			logging.warning("Hospitalizing message: Unknown subject (" + subject + ")")
			return (None, None, "", "", "unknown_subject")
		(send_ts, hospital_reason, tzname) = cls.parseUTCDateTime(m.group(2))
		if hospital_reason:
			logging.warning("Hospitalizing message: Failed in parsing send time")
			return (None, None, "", "", "send_ts_" + hospital_reason)
		else:
			logging.debug("Received on: " + send_ts.strftime(r"%d/%m/%Y %H:%M:%S %Z"))
		crash_str = cls.parseSimpleValue(body, "Report Generated", ": ")
		if not crash_str:
			logging.warning("Hospitalizing message: Missing generated time line in body")
			return (None, None, "", "", "crash_time_missing")
		(crash_ts, hospital_reason, tzname) = cls.parseUTCDateTime(crash_str)
		if hospital_reason:
			logging.warning("Hospitalizing message: Failed in parsing crash time")
			return (None, None, "", "", "crash_ts_" + hospital_reason)
		else:
			logging.debug("Crashed on: " + crash_ts.strftime(r"%d/%m/%Y %H:%M:%S %Z"))
		signature = cls.getCrashSignature(body)
		if signature:
			logging.debug("Signature: '" + signature + "'")
		else:
			logging.warning("Hospitalizing message: No signature found")
			return (None, None, "", "", "no_signature")
		return (send_ts, crash_ts, signature, tzname, "")
	def parseReport(self):
		(send_ts, crash_ts, signature, tzname, hospital_reason) = CrashReport.getMessageEssentials(self.crashId, self.report)
		if hospital_reason:
			return hospital_reason
		self.packageName = self.parseSimpleValue(self.report, "PackageName")
		self.versionName = self.parseSimpleValue(self.report, "VersionName").strip()
		self.crashSignature = signature
		self.signHash = hashlib.sha1(signature).hexdigest()
		self.crashTime = crash_ts
		self.crashTz = tzname
		self.sendTime = send_ts
		self.board = self.parseSimpleValue(self.report, "Board")
		self.brand = self.parseSimpleValue(self.report, "Brand")
		self.model = self.parseSimpleValue(self.report, "Model")
		self.product = self.parseSimpleValue(self.report, "Product")
		self.device = self.parseSimpleValue(self.report, "Device")
		self.display = self.parseSimpleValue(self.report, "Display")
		self.androidOSId = self.parseSimpleValue(self.report, "ID")
		self.androidOSVersion = self.parseSimpleValue(self.report, "AndroidVersion")
		try:
			self.availableInternalMemory = long(self.parseSimpleValue(self.report, "AvailableInternalMemory"))
		except ValueError:
			logging.warning("Hospitalizing message: Failed in parsing available internal memory: '" + self.parseSimpleValue(self.report, "AvailableInternalMemory") + "'")
			return "avail_mem_parse_error"
		try:
			self.totalInternalMemory = long(self.parseSimpleValue(self.report, "TotalInternalMemory"))
		except ValueError:
			logging.warning("Hospitalizing message: Failed in parsing total internal memory: '" + self.parseSimpleValue(self.report, "TotalInternalMemory") + "'")
			return "total_mem_parse_error"
		#self.put()
		return ""

class LogSenderHandler(InboundMailHandler):
	def receive(self, mail_message):
		encoded_subject = decode_header(mail_message.subject)
		subject = encoded_subject[0][0]
		encoding = encoded_subject[0][1]
		if encoding:
			subject = subject.decode(encoding)
			logging.debug("Decoded subject: '" + subject + "' encoding: '" + encoding)
		if not isinstance(subject, unicode):
			subject = unicode(subject)
			logging.debug("Converted subject to unicode:: '" + subject + "'")
		subject = re.sub('\n', '', subject)
		logging.info("Message from: " + mail_message.sender + " - Subject: " + subject)
		body = ''
		try:
			# Get the body, try the html version, if not found we convert the plain to html
			body = mail_message.bodies('text/html').next()[1].decode()
		except StopIteration:
			logging.warning("Can't find html body, will use text/plain instead")
		if not body:
			try:
				body = mail_message.bodies('text/plain').next()[1]
				if body.encoding == '8bit':
					body = body.payload
					logging.warning("Un-decoded body: '" + body + "'")
				else:
					body = body.decode()
				logging.debug("Message decoded: '" + body + "'")
				body = escape(body)
				body = re.sub(r"\n", "<br>", body)
				logging.debug("Message escaped: '" + body + "'")
			except StopIteration:
				logging.error("Rejecting message: Can't retrieve even text/plain body of mail")
				raise
		# Convert paragraphs to <br>
		body = re.sub(r"<p>", "", body)
		body = re.sub(r"</p>", "<br>", body)
		body = re.sub(r"<br\s*/>", "<br>", body, re.U)
		# Escape the report BEGIN/END marks so they are not killed as tags
		body = re.sub(r"-->\s*((BEGIN)|(END))\s+REPORT\s+(\d+)\s*<--", r"--&gt; \1 REPORT \4 &lt;--", body, re.U)
		# Remove anything following the END of REPORT (like personal email signatures)
		m = re.search(r'^(.*--\&gt; END REPORT \d \&lt;--).*$', body, re.S)
		if m:
			body = m.group(1)
		# Strip all tags except <br>
		body = re.sub(r'<(?!br/?>)[^>]+>', '', body)
		# Strip tabs of the form &#09;
		body = re.sub(r'&#0?9;', ' ', body)
		cr = CrashReport(crashId = subject, report = body)
		hospital_reason = cr.parseReport()
		if hospital_reason:
			logging.info("Hospitalized body: '" + body)
			hr = HospitalizedReport(crashId=subject,
					crashBody=body,
					diagnosis=hospital_reason,
					processed=False)
			hr.put()
		else:
			# check for duplicates
			dupl_query = CrashReport.all()
			dupl_query.filter("crashId =", cr.crashId)
			if dupl_query.count(1) == 0:
				cr.put()
				cr.linkToBug()
				AppVersion.insert(cr.versionName, cr.crashTime)
			else:
				dupl = dupl_query.fetch(1)[0]
				logging.warning("Found duplicate with id: " + str(dupl.key().id()))

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
		micros = dt[1][:6]
		ts = ts + timedelta(microseconds = long(micros + "000000"[len(micros):]))
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
				fb.put()
				self.response.out.write("OK")
			else:
				self.error(400)
		else:
			self.error(400)

class HttpCrashReceiver(webapp.RequestHandler):
	def parseDateTime(self, dtstr):
		dt = dtstr.split('.')
		ts = datetime.strptime(dt[0], r'%Y-%m-%dT%H:%M:%S')
		micros = dt[1][:6]
		ts = ts + timedelta(microseconds = long(micros + "000000"[len(micros):]))
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
#	def getCrashSignature(self, body):
#		signLine1 = ''
#		signLine2 = ''
#		cleanbody = re.sub(r"<br></br>", "\n", body)
#		cleanbody = re.sub(r"<br\s*/?>", "\n", cleanbody)
#		#m1 = re.search(r"Begin Stacktrace[\s\n]*([^<\s][^<\n]*[^<\s][\s\n]*at\s[^<\n]*)", body, re.M|re.U)
#		#		Begin Stacktrace\s*(\n\s*)*([^<\s][^<\n]*[^<\s]\s*\n\s*at\s[^<\n]*)", body, re.M|re.U)
#		#m1 = re.search(r"Begin Stacktrace[\s\n]*([^\n]*\n\s*at[^\n]*[^\s])\s*\n", body, re.M|re.U)
#		m1 = re.search(r"Begin Stacktrace[\s\n]*([^)]*?\))[\n\s]*at[\n\s]", cleanbody, re.M|re.U)
#		if m1:
#			signLine1 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m1.group(1))
#			logging.debug('Sign m1: %s' % m1.group(1))
#		#m2 = re.search(r"\n\s*(at\scom\.(ichi2|mindprod|samskivert|tomgibara|hlidskialf)\.[^\n]*[^\s])\s*\n", body, re.M|re.U)
#		m2 = re.search(r"[\n\s]*(at\scom\.(ichi2|mindprod|samskivert|tomgibara|hlidskialf)\.[^)]*?\))[\s\n]*at[\n\s]", cleanbody, re.M|re.U)
#		if m2:
#			signLine2 = re.sub(r"(\$[0-9A-Za-z_]+@)[a-f0-9]+", r"\1", m2.group(1))
#			logging.debug('Sign m2: %s' % m2.group(1))
#		return signLine1 + "\n" + signLine2
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
						logging.info("ts: " + sendTime.astimezone(tz).strftime("%a %b %d %H:%M:%S %%s %Y"))
						_crashId = 'HTTP Bug Report on %s num: %03d' % (sendTime.astimezone(tz).strftime("%a %b %d %H:%M:%S %%s %Y"), _index)
						_crashId = _crashId % sendtz
						logging.info("HTTP report: " + _crashId)
						cr = CrashReport(crashId = _crashId, report = body)
						self.parseEssentials(cr, self.request, signature, _groupId, _index)
						cr.put()
						cr.linkToBug()
						AppVersion.insert(cr.versionName, cr.crashTime)
						if cr.bugKey.count == 1:
							self.response.out.write("new")
						else:
							issueName = cr.bugKey.issueName
							if issueName is None:
								self.response.out.write("known")
							else:
								self.response.out.write("issue:%d:%s" % (cr.bugKey.issueName, cr.bugKey.status))
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
	application = webapp.WSGIApplication([LogSenderHandler.mapping(),
		(r'^/crash_receiver/?.*', HttpCrashReceiver),
		(r'^/feedback_receiver/?.*', HttpFeedbackReceiver)], debug=True)
	run_wsgi_app(application)

if __name__ == '__main__':
	main()

