import dramatiq

from account.models import User
from submission.models import Submission
from judge.dispatcher import JudgeDispatcher
from utils.shortcuts import DRAMATIQ_WORKER_ARGS


@dramatiq.actor(**DRAMATIQ_WORKER_ARGS())
def judge_task(submission_id, problem_id, updated_result=None):
    uid = Submission.objects.get(id=submission_id).user_id
    if User.objects.get(id=uid).is_disabled:
        return
    if updated_result is None:
        JudgeDispatcher(submission_id, problem_id).judge()
    else:
        JudgeDispatcher(submission_id, problem_id).manual_judge(updated_result)
