import hashlib
from mapreduce import operation as op
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
