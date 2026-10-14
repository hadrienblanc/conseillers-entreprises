require 'rails_helper'

# Security regression test (finding F1 — IDOR in FeedbacksController#create).
#
# A standard, non-admin user from an unrelated antenne must NOT be able to:
#   * create a `need` Feedback on a Need that is outside their perimeter
#     (NeedPolicy#show? is false for them on that Need),
#   * nor trigger MatchFeedbackEmailJob towards the experts matched on that Need
#     (those experts would then receive the injected comment by email, and the
#     comment is rendered publicly on the need page for all its participants).
#
# This test asserts the SECURE behaviour. It currently FAILS, which demonstrates
# the vulnerability: FeedbackPolicy#create? only checks the feedback category
# (`need`), never the caller's perimeter on `feedbackable`.
RSpec.describe 'Feedbacks', type: :request do
  describe 'POST /feedbacks with feedbackable = a Need outside the caller perimeter' do
    let(:attacker) { create :user } # standard user: no admin right, no expert, unrelated antenne
    let(:need) { create :need_with_matches } # advisor/experts belong to other antennes
    let(:expert) { need.matches.first.expert }

    before do
      # The expert has taken the match: they are a notification target for
      # Feedback#persons_to_notify (matches in taking_care / done_not_reachable).
      need.matches.first.update(status: :taking_care)
      login_as attacker, scope: :user
    end

    it 'confirms the attacker is outside the need perimeter (NeedPolicy#show? is false)' do
      # Contrast assertion: reading the need is already denied to the attacker…
      expect(NeedPolicy.new(attacker, need).show?).to be_falsey
    end

    it 'does not create the feedback on the need of another antenne' do
      expect do
        post '/feedbacks', params: { feedback: {
          description: 'POC IDOR: commentaire injecte sur un besoin hors perimetre',
          feedbackable_id: need.id,
          feedbackable_type: 'Need',
          category: 'need'
        } }
      end.not_to change(Feedback, :count)

      expect(Feedback.where(feedbackable: need, user: attacker)).to be_empty
    end

    it 'does not enqueue MatchFeedbackEmailJob towards the experts of the need' do
      post '/feedbacks', params: { feedback: {
        description: 'POC IDOR: commentaire injecte sur un besoin hors perimetre',
        feedbackable_id: need.id,
        feedbackable_type: 'Need',
        category: 'need'
      } }

      feedback_email_jobs = enqueued_jobs.select { |job| job[:job] == MatchFeedbackEmailJob }
      expect(feedback_email_jobs).to be_empty
    end

    it 'does not redirect the attacker to the victim need page' do
      post '/feedbacks', params: { feedback: {
        description: 'POC IDOR: commentaire injecte sur un besoin hors perimetre',
        feedbackable_id: need.id,
        feedbackable_type: 'Need',
        category: 'need'
      } }

      # The app redirects the attacker straight to the (otherwise forbidden) need page
      expect(response.location).not_to start_with(need_url(need))
    end
  end
end
