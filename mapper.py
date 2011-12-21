import hashlib, logging
from datetime import datetime
from mapreduce import operation as op
from google.appengine.api import taskqueue
from receive_ankicrashes import CrashReport

def rebuild_signatures(entity):
	signature = CrashReport.getCrashSignature(entity.report)
	entity.crashSignature = signature
	entity.signHash = hashlib.sha1(signature).hexdigest()
	entity.adminOpsflag = 6
	entity.bugkey = None
	entity.linkToBug(False)
	yield op.db.Put(entity)

def delete_bugs(entity):
	yield op.db.Delete(entity)

def delete_duplicates(entity):
	yield op.counters.Increment("total-counter")
	dupl_query = CrashReport.all(keys_only=True)
	dupl_query.filter('crashTime =', entity.crashTime)
	matched_crashes = dupl_query.fetch(50000)
	mustDelete = False
	counted = False
	matched = False
	if len(matched_crashes) > 1:
		for crkey in matched_crashes:
			cr = CrashReport.get(crkey)
			if cr.availableInternalMemory == entity.availableInternalMemory:
				matched = True
				if not counted:
					counted = True
					yield op.counters.Increment("individual-counter")
				if cr.sendTime < entity.sendTime:
					mustDelete = True
					break
	if mustDelete:
		yield op.counters.Increment("delete-counter")
		yield op.db.Delete(entity)
	else:
		if matched:
			yield op.counters.Increment("survivor-counter")
		else:
			yield op.counters.Increment("single-counter")

def fix_crash_ts(entity):
	#entity.lastIncident = entity.lastIncident.replace(microsecond=0)
	entity.sendTime = entity.sendTime.replace(microsecond=0)
	yield op.db.Put(entity)

def recalc_counts_on_bugs(entity):
	crash_query = CrashReport.all(keys_only=True)
	crash_query.filter('signHash =', entity.signHash)
	crash_query.order('-crashTime')
	newcount = crash_query.count(50000)
	if entity.count != newcount:
		entity.count = newcount
		cr = CrashReport.get(crash_query.fetch(1)[0])
		entity.lastIncident = cr.crashTime
		#logging.warning("Wrong count for bug %d, adjusting to %d" % entity.key().id(), count)
		yield op.counters.Increment("touched-bugs")
		yield op.db.Put(entity)
	if newcount == 0:
		yield op.counters.Increment("empty-bugs")
	yield op.counters.Increment("crash-counter", newcount)

def recalc_counts_on_vesions(entity):
	crash_query = CrashReport.all(keys_only=True)
	crash_query.filter('versionName =', entity.name)
	crash_query.order('-crashTime')
	newcount = crash_query.count(20000)
	if entity.crashCount != newcount:
		entity.crashCount = newcount
		cr = CrashReport.get(crash_query.fetch(1)[0])
		entity.lastIncident = cr.crashTime
		#logging.warning("Wrong count for bug %d, adjusting to %d" % entity.key().id(), count)
		yield op.counters.Increment("touched-versions")
		yield op.db.Put(entity)
	if newcount == 0:
		yield op.counters.Increment("empty-versions")
	yield op.counters.Increment("crash-counter", newcount)

def delete_auto_feedback(entity):
	if entity.message == 'Automatically sent':
		yield op.db.Delete(entity)
		yield op.counters.Increment("deleted")

def gen_crash_export(entity):
	q = taskqueue.Queue('crash-export-queue')
	q.add((taskqueue.Task(payload=entity.getExportLine(), method='PULL')))
	yield op.counters.Increment("added")

def gen_bug_export(entity):
	q = taskqueue.Queue('bug-export-queue')
	q.add((taskqueue.Task(payload=entity.getExportLine(), method='PULL')))
	yield op.counters.Increment("added")

def gen_feedback_export(entity):
	q = taskqueue.Queue('feedback-export-queue')
	q.add((taskqueue.Task(payload=entity.getExportLine(), method='PULL')))
	yield op.counters.Increment("added")

