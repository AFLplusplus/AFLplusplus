"""Sovereign Brain conversational interface with local Admin tools."""
import json
import os
import re
import uuid
from pathlib import Path

import streamlit as st
from dotenv import load_dotenv, find_dotenv

# Resolve .env relative to this app even in Streamlit or non-interactive launchers.
# Existing process/user environment values always take precedence.
load_dotenv(find_dotenv(filename='.env', usecwd=True) or Path(__file__).resolve().with_name('.env'), override=False)

from brain_core import conversation, lessons, personality, service, studio, trainer
from brain_core import cloud_orchestration
from brain_core.appraisal import NEUTRAL
from brain_core.model_api import (ModelConfig, ModelError, ModelOutputError, local_inventory,
                                  alibaba_configuration)
from brain_core.model_policy import policy_for, selected_local_model
from brain_core.runtime_guard import available_memory_gib
from brain_core.decision import emotional_transition
from brain_core.cloud_runtime import MANAGER as _DEFAULT_CLOUD_APPROVALS
from brain_core.providers import AlibabaQwenProvider, sanitized_cloud_context


CLOUD_CONSENT = _DEFAULT_CLOUD_APPROVALS
CLOUD_SERVICE_FACTORY = cloud_orchestration.CloudOrchestrator
CLOUD_PAYLOAD_FACTORY = None
CLOUD_PROVIDER_FACTORY = AlibabaQwenProvider
CLOUD_API_KEY = lambda: os.getenv('DASHSCOPE_API_KEY', '')


st.set_page_config(page_title='Sovereign Brain', page_icon='🧠', layout='wide')
st.title('🧠 Sovereign Brain')
st.caption('A local conversational space · simulated emotional indexes are not feelings or consciousness.')

try:
    profile = personality.inspect()
    if profile is None:
        st.warning('No persistent personality profile exists yet. It will be initialized only when you explicitly start training.')
        profile = dict(personality.DEFAULT)
except (personality.PersonalityError, OSError):
    st.error('The established personality is missing, invalid, or unreadable. No identity was reset. Restore it from backup.')
    st.stop()


@st.cache_data(ttl=10)
def installed_models():
    return local_inventory()


def _model_configuration():
    models = installed_models()
    model = selected_local_model()
    policy = policy_for(model)
    ready = model in models
    config, error = None, None
    with st.sidebar:
        st.radio('Workspace', ['Conversation', 'Admin'], index=0, key='workspace_page',
                 horizontal=True, label_visibility='collapsed')
        st.subheader('Model connection')
        cloud = alibaba_configuration()
        st.caption(f"Cloud Qwen · approval per request · key configured: {cloud.api_key_configured} · region: {cloud.region or 'not configured'} · workspace: {'configured' if cloud.workspace_id else 'not configured'} · model: {cloud.model or 'not configured'}")
        if cloud.errors:
            st.caption('Cloud configuration incomplete: ' + ' '.join(cloud.errors))
        mode = st.radio('Inference', ['Local model (Ollama)', 'Enterprise gateway', 'Offline demonstration'],
                        index=0 if ready else 2, key='studio_inference')
        remote_authorized = False
        if mode == 'Offline demonstration':
            st.caption('Offline demonstration responses are fixtures, not model reasoning.')
        elif mode == 'Local model (Ollama)':
            config = ModelConfig(model=model)
            st.caption(f'Local endpoint · {model} · detected: {ready}')
            if not ready and not str(model).startswith('offline-only-test-model'):
                error = 'Local model is not installed or Ollama is not responding.'
        else:
            remote_authorized = st.checkbox('Authorize sending this session to the configured enterprise gateway.', value=False)
            try:
                config = ModelConfig.from_env(allow_remote=remote_authorized)
                if config.local:
                    error = 'Configure BRAIN_API_BASE and BRAIN_MODEL for the gateway.'
            except (ModelError, ValueError):
                error = 'A valid HTTPS gateway and explicit authorization are required.'
        available = available_memory_gib()
        if available is None and mode == 'Local model (Ollama)':
            error = 'Cannot verify available physical RAM; local inference is paused.'
        elif available is not None and available < policy.minimum_available_gib:
            st.caption(f'Local inference held: {available:.2f} GiB available; {policy.minimum_available_gib:.1f} GiB required.')
            if ready and mode == 'Local model (Ollama)':
                error = 'Local inference is held by its memory safety check.'
        if error:
            st.warning(error)
        if st.button('Refresh connection status'):
            installed_models.clear()
            st.rerun()
        st.divider()
        with st.expander('Persistent identity'):
            st.write(profile['identity_name'])
            st.caption('Identity: ' + profile['identity_id'])
            st.write(profile['mission'])
            for name, value in profile['traits'].items():
                st.progress(float(value), text=f'{name.replace("_", " ").title()}: {value:.2f}')
    return mode, remote_authorized, model, ready, config, error


def _alibaba_endpoint_from_settings(settings):
    """Return the validated explicit endpoint, or the configured derived endpoint."""
    if not settings.configured or not settings.endpoint:
        raise ValueError(' '.join(settings.errors) or 'Alibaba endpoint is not configured.')
    return settings.endpoint.rstrip('/')


def _make_cloud_payload(user_text, profile, approved_lessons, *, session_id):
    settings = alibaba_configuration()
    endpoint = _alibaba_endpoint_from_settings(settings)
    context = sanitized_cloud_context(scenario=user_text, identity_name=profile.get('identity_name','Sovereign Brain'),
        identity_mission=profile.get('mission',''), approved_lessons=approved_lessons)
    system = ('You are the pretrained reasoning engine serving Sovereign Brain, not its identity owner. '
              'Follow the supplied stable identity guidance. Return JSON matching the supplied schema. '
              'Reason through UNDERSTAND (facts, feelings reported by the user, assumptions, relevant approved lesson IDs), '
              'EVALUATE (alternatives, uncertainty, boundaries, consequences), and DECIDE (proportionate action, rationale, next step). '
              'Never invent evidence or infer hidden third-party motives. Prior lessons are principles, not event facts.')
    schema = {'type':'object','properties':{
        'version':{'type':'string','enum':['sovereign-reasoning.v1']}, 'facts':{'type':'array','items':{'type':'string','minLength':1,'maxLength':500},'minItems':1,'maxItems':5},
        'assumptions':{'type':'array','items':{'type':'string','minLength':1,'maxLength':500},'minItems':1,'maxItems':5},
        'emotional_interpretation':{'type':'string','minLength':1,'maxLength':1000}, 'alternatives':{'type':'array','items':{'type':'string','minLength':1,'maxLength':500},'minItems':2,'maxItems':4},
        'recommended_action':{'type':'string','minLength':1,'maxLength':500},'rationale':{'type':'string','minLength':1,'maxLength':1000},'next_step':{'type':'string','minLength':1,'maxLength':500},
        'lesson_ids_used':{'type':'array','items':{'type':'string'},'maxItems':3}},
        'required':['version','facts','assumptions','emotional_interpretation','alternatives','recommended_action','rationale','next_step','lesson_ids_used'],
        'additionalProperties':False}
    payload={'model':settings.model,'messages':[
        {'role':'system','content':system},
        {'role':'user','content':json.dumps(context,ensure_ascii=False)}],
        'stream':False,'temperature':0.2,'max_tokens':min(768,int(os.getenv('SOVEREIGN_ALIBABA_MAX_OUTPUT_TOKENS','768'))),
        'response_format':{'type':'json_schema','json_schema':{'name':'sovereign_reasoning_v1','strict':True,'schema':schema}}}
    return settings,endpoint,payload,schema


def model_request_payload(payload, request):
    """Build the provider request from the exact preview payload without broadening it."""
    return request


def _cloud_result_writer(session_id, result, approved_lessons=()):
    if result.status != 'success' or not isinstance(result.structured, dict):
        return
    data = result.structured
    if (data.get('version') != 'sovereign-reasoning.v1' or not data.get('facts')
            or not data.get('assumptions') or len(data.get('alternatives', [])) < 2):
        return
    approved_ids = {lesson.get('lesson_id') for lesson in approved_lessons}
    cited_ids = data.get('lesson_ids_used', [])
    if not isinstance(cited_ids, list) or set(cited_ids) - approved_ids:
        return
    from brain_core.reasoning_stages import conversational_response
    normalized = {'_stage_outputs': {
        'understanding': {'facts': data['facts'], 'emotions': [{'label': data.get('emotional_interpretation', ''),
            'trigger': data.get('emotional_interpretation', '')}], 'assumptions': data['assumptions']},
        'alternatives': {'alternatives': [{'action': action, 'consequence': data.get('rationale', '')}
            for action in data['alternatives']]},
        'final_decision': {'selected_action': data.get('recommended_action', ''),
            'rationale': data.get('rationale', '')}},
        '_provenance': {'approved_lessons': [lesson for lesson in approved_lessons
            if lesson.get('lesson_id') in cited_ids]},
        '_validation': {'schema_passed': True, 'cognitive_checks_passed': True}}
    try:
        answer = conversational_response(normalized)
    except (KeyError, TypeError, ValueError):
        return
    _save_response(session_id, answer, 'cloud_reasoning', 'authorized')


def _account_cloud_result(*, request, result, conversation_id):
    CLOUD_CONSENT.record_result(
        request.approval_id, success=result.status == 'success',
        input_tokens=getattr(result, 'input_tokens', None),
        output_tokens=getattr(result, 'output_tokens', None),
        reported_cost_usd=getattr(result, 'reported_cost_usd', None),
        error_category=getattr(result, 'error_category', None))


def _cloud_service():
    services = st.session_state.setdefault('_cloud_services_by_conversation', {})
    conversation_id = st.session_state.get('conversation_id')
    if conversation_id not in services or not hasattr(services[conversation_id], 'prepare_fallback'):
        services[conversation_id] = CLOUD_SERVICE_FACTORY(
            consent=CLOUD_CONSENT,
            payload_factory=CLOUD_PAYLOAD_FACTORY or _make_cloud_payload,
            provider_factory=CLOUD_PROVIDER_FACTORY,
            api_key=CLOUD_API_KEY,
            provider_payload=model_request_payload,
            provider_fingerprint=lambda request, payload: AlibabaQwenProvider.fingerprint(request),
            result_writer=_cloud_result_writer,
            result_accountant=_account_cloud_result)
    return services[conversation_id]


def _render_cloud_approval(session_id):
    services = st.session_state.setdefault('_cloud_services_by_conversation', {})
    cloud_service = services.get(session_id)
    if cloud_service is not None and hasattr(cloud_service, 'get_pending_request'):
        request = cloud_service.get_pending_request(session_id)
        if request is not None:
            pending = {'conversation_id': request.conversation_id,
                       'request': request, 'service': cloud_service}
        else:
            pending = None
    else:
        pending = None
    other_pending = next(((key, service, service.get_pending_request(key))
                          for key, service in services.items()
                          if key != session_id and hasattr(service, 'get_pending_request')
                          and service.get_pending_request(key) is not None), None)
    if pending is None and other_pending is not None:
        st.info('A cloud request is pending in another conversation. Switch back to its original conversation to review or cancel it.')
        other_id, other_service, other_request = other_pending
        if st.button('Cancel pending cloud request', key='cancel_cloud_request'):
            other_service.decline_fallback(request=other_request, conversation_id=other_id)
            st.warning('Pending cloud request canceled; no external request was sent.')
        return
    if pending is None:
        return
    request = pending.get('request')
    cloud_service = pending.get('service')
    if request is None or cloud_service is None:
        st.error('Cloud request state is unavailable. No external request was sent.')
        return
    st.warning('Cloud Qwen requires approval for this one request. Decline is the default; no request has been sent.')
    st.write(f"Provider: Alibaba Cloud Model Studio · Model: {request.model} · Region: {request.region}")
    st.write('Reason: local inference was unavailable or its reasoning checks did not pass.')
    st.write(f"Estimated prompt tokens: about {request.token_estimate} · maximum output tokens: {request.max_output_tokens}")
    st.caption('Cost is not verifiably available from local configuration. Check provider-side quota/billing controls; no exact cost is claimed.')
    st.caption('Payload fingerprint: ' + request.fingerprint)
    with st.expander('Exact minimized payload to be transmitted', expanded=True):
        st.code(request.payload_json, language='json')
    left, right = st.columns(2)
    if left.button('Approve this cloud request once', key='approve_cloud_once'):
        try:
            execution = cloud_service.approve_and_execute(request=request, conversation_id=session_id)
            result = execution.result
            if result.status != 'success' or not isinstance(result.structured, dict):
                st.error(f"Cloud request failed ({result.error_category}). It was not retried.")
            else:
                st.success(f"Cloud Qwen · {result.model} · request {result.request_id or 'ID unavailable'} · {result.latency_seconds:.2f}s. This is not proof of psychological reliability.")
            st.session_state.cloud_services = services
        except cloud_orchestration.CloudOrchestrationError:
            st.error('Cloud authorization or request failed safely. No automatic retry was attempted.')
    if right.button('Decline cloud; keep request local', key='decline_cloud_once'):
        if cloud_service.decline_fallback(request=request, conversation_id=session_id):
            _save_response(session_id, 'Cloud inference was declined. Your message and any retrieved approved memory remain available; no external request was sent, and no lesson or emotional state was modified.', 'cloud_declined', 'declined')
            st.info('Cloud request declined. Your message and retrieved approved memory remain available; no external request was sent.')
        st.session_state.cloud_services = services


def _offer_cloud_fallback(user_text, session_id, profile, approved_lessons, *, local_error):
    cloud_service = _cloud_service()
    try:
        request = cloud_service.prepare_fallback(
            user_text=user_text, conversation_id=session_id, profile=profile,
            approved_lessons=approved_lessons, local_error=local_error,
            eligible=True)
        services = st.session_state.setdefault('_cloud_services_by_conversation', {})
        services[session_id] = cloud_service
        st.session_state.cloud_services = services
        st.info(f"Local reasoning is unavailable ({type(local_error).__name__}). Cloud Qwen is only an option; nothing has been sent.")
    except cloud_orchestration.CloudOrchestrationError:
        st.warning(f"Local reasoning is unavailable ({type(local_error).__name__}); cloud configuration is incomplete or exceeds a safety limit. Your message is preserved and no external request was sent.")


def _unused_render_admin_duplicate(profile, mode, remote_authorized, model, ready, configuration_error):
    """Duplicate draft retained temporarily while preserving the established Admin UI below."""
    st.subheader('Administrator tools')
    st.caption('Local technical and memory tools. This section is not authentication; keep access bound to loopback.')
    state, history = trainer.inspect_status()
    if state is None:
        state = {'iterations': 0, 'emotion': 'neutral', 'metrics': dict(trainer.BASE), 'emotions': dict(NEUTRAL)}
    with st.expander('Model settings and system health'):
        cloud = alibaba_configuration()
        st.write('Cloud Qwen: approval required for every inference · API key configured:', cloud.api_key_configured)
        if cloud.errors:
            st.caption('Cloud configuration incomplete: ' + ' '.join(cloud.errors))
        st.write('Alibaba region:', cloud.region or 'not configured', '· workspace configured:', bool(cloud.workspace_id),
                 '· endpoint configured:', bool(cloud.endpoint), '· selected model:', cloud.model or 'not configured')
        st.caption('Configuration presence is not proof of API callability. No health-check inference is sent.')
        st.write('Configured model:', model, '· detected:', ready)
        st.write('Inference selection:', mode, '· remote authorization:', remote_authorized)
        st.write('Inference status:', configuration_error or 'Ready subject to per-request validation.')
        st.write('Local Ollama installed models:', ', '.join(installed_models()) or 'not detected')
        st.write('Available RAM (GiB):', available_memory_gib())
        st.write('Saved turns:', len(studio.inspect_turns(1000)))
        st.write('Persistent identity:', profile.get('identity_name'), profile.get('identity_id'))
        if st.button('Refresh model status', key='admin_refresh_models'):
            installed_models.clear()
            st.rerun()
    with st.expander('Emotional-state inspection'):
        st.json(state)
    with st.expander('Approved lessons'):
        records = lessons.list_lessons(data_dir=studio.DATA, db_path=studio.DB)
        if records:
            for item in records:
                st.write(item['scenario_summary'], '·', item['corrective_principle'], '·', item['approval_status'])
        else:
            st.caption('No approved lessons are available.')
    with st.expander('Training and retrieval'):
        st.caption('Training proposals require explicit review. Approved lessons are read-only context during retrieval.')
        upload = st.file_uploader('Upload a reference document', type=['txt', 'md', 'pdf', 'docx'])
        if upload is not None and st.button('Import reference document'):
            try:
                studio.add_document(upload.name, studio.decode_document(upload.name, upload.getvalue()))
                st.success('Reference document imported locally.')
            except Exception:
                st.warning('Document import failed. Check type, size and readable text.')
        with st.form('admin_research'):
            topic = st.text_input('Research question', max_chars=500)
            search = st.form_submit_button('Find evidence')
        if search and topic.strip():
            try:
                st.write(studio.research_search(topic))
            except Exception:
                st.warning('Research unavailable; check the optional local research configuration.')
        for item in studio.inspect_research_items():
            with st.expander(item['title'] or item['url']):
                st.write(item['url'], item['excerpt'])
                approved = st.checkbox('Approve as reference evidence', value=bool(item['approved']), key=f"research_{item['id']}")
                if st.button('Save research approval', key=f"approve_research_{item['id']}"):
                    studio.approve_research(item['id'], bool(approved))
                    st.rerun()
    with st.expander('Cognitive diagnostics'):
        diagnostic_dir = os.environ.get('BRAIN_DIAGNOSTIC_DIR')
        if diagnostic_dir and Path(diagnostic_dir).is_dir():
            for path in sorted(Path(diagnostic_dir).glob('*.json'))[-20:]:
                try:
                    st.json(json.loads(path.read_text(encoding='utf-8')))
                except Exception:
                    st.caption('A diagnostic record could not be read.')
        else:
            st.caption('No configured local diagnostic directory was found.')
    with st.expander('Legacy trainer workflow', expanded=False):
        st.session_state.setdefault('admin_result_review', None)
        scenario = st.text_area('Situation', height=135, max_chars=8000)
        context = st.text_area('Context and relationships (optional)', height=80, max_chars=3000)
        label = st.text_input('Relationship or context label (optional)', max_chars=100)
        guidance = st.text_area('Trainer guidance (optional)', height=75, max_chars=4000)
        use_memory = st.checkbox('Retrieve previous trainer corrections', value=True)
        use_refs = st.checkbox('Use uploaded documents and approved research', value=False)
        combined = scenario.strip() + ('\\n\\nContext and relationships: ' + context.strip() if context.strip() else '')
        retry_pending = st.session_state.get('admin_retry_pending', False)
        if st.button('Analyze emotions and decide', type='primary', key='admin_analyze', disabled=not scenario.strip() or bool(configuration_error)) or retry_pending:
            st.session_state.admin_retry_pending = False
            try:
                with st.spinner('Analyzing locally...'):
                    turn_id, updated, result, retrieved = service.analyze(
                        combined, guidance, mock=(mode == 'Offline demonstration'),
                        config=ModelConfig(model=model) if mode == 'Local model (Ollama)' else None,
                        use_references=use_refs, use_feedback=use_memory, relationship_label=label,
                        state_path=trainer.STATE_PATH, history_path=trainer.HISTORY_PATH,
                        data_dir=studio.DATA, db_path=studio.DB, profile_path=personality.PROFILE_PATH,
                        persist_fixture_state=(mode == 'Offline demonstration'))
                st.session_state.studio_last_turn = turn_id
                st.session_state.studio_result = result
                st.session_state.admin_result_review = result
                st.session_state.studio_state = updated
                st.session_state.studio_feedback = retrieved
                st.rerun()
            except ModelOutputError as error:
                st.error('The model response did not meet reasoning quality checks. No training or emotional state was changed.')
                if error.diagnostic_id:
                    st.caption(f'Diagnostic reference: {error.diagnostic_id}')
                if st.button('Retry analysis', key='admin_retry_analysis'):
                    st.session_state.admin_retry_pending = True
                    st.rerun()
            except (ModelError, ValueError):
                st.error('Analysis failed or was unavailable. No result is claimed.')
        if st.session_state.get('admin_result_review') is not None:
            result = st.session_state.admin_result_review
            provenance = result.get('_provenance', {})
            st.subheader('Decision review')
            st.caption(f"Source: {provenance.get('source', 'unknown')} · Model: {provenance.get('model', 'not recorded')}")
            st.write(result.get('narrative', 'No narrative available.'))
            decision = result.get('decision', {})
            if decision:
                left, right = st.columns(2)
                with left:
                    st.markdown('**Competing emotions**')
                    for emotion in decision.get('conflicting_emotions', []):
                        st.write('• ' + emotion)
                    st.markdown('**Evidence and uncertainty**')
                    st.write(decision.get('evidence', ''))
                    st.write(decision.get('uncertainty', ''))
                with right:
                    st.markdown('**Options considered**')
                    for option in decision.get('options', []):
                        st.write('• ' + option)
                    st.markdown('**Proposed decision and rationale**')
                    st.write(decision.get('recommended_action', ''))
                    st.write(decision.get('rationale', ''))
            transition = emotional_transition(result, st.session_state.get('studio_state') or state)
            try:
                st.bar_chart(transition, x='Emotion', y=['Before', 'After'], horizontal=True, stack=False)
                st.dataframe(transition, hide_index=True, width='stretch')
            except (ImportError, ModuleNotFoundError):
                st.json(transition)
            st.json(result.get('_cognitive_context', {}))
            if result.get('_trainer_pending'):
                st.warning('This decision is pending explicit approval. No learning or simulated state update is committed yet.')
            rating = st.radio('Rate emotional appropriateness', ['good', 'partial', 'poor'], horizontal=True,
                              key=f"admin_rating_{st.session_state.studio_last_turn}")
            correction = st.text_area('Correct the response / challenge its recommendation', max_chars=4000,
                                      key=f"admin_correction_{st.session_state.studio_last_turn}")
            if st.button('Save trainer feedback', key='admin_save_feedback'):
                if provenance.get('source') == 'offline_fixture':
                    st.warning('Offline demonstration fixtures cannot be approved as training.')
                elif result.get('_trainer_pending'):
                    approved_result = dict(result, _trainer_approved=True)
                    approved_result.pop('_trainer_pending', None)
                    approved_result['_provenance'] = dict(provenance, source='approved_training')
                    try:
                        approved_turn, updated, saved_result, _ = service.analyze(
                            combined, guidance, config=ModelConfig(model=model) if mode == 'Local model (Ollama)' else None,
                            use_references=use_refs, use_feedback=use_memory, relationship_label=label,
                            state_path=trainer.STATE_PATH, history_path=trainer.HISTORY_PATH,
                            data_dir=studio.DATA, db_path=studio.DB, profile_path=personality.PROFILE_PATH,
                            approved_result=approved_result)
                        approved_turn = approved_turn or st.session_state.studio_last_turn
                        st.session_state.studio_last_turn = approved_turn
                        st.session_state.studio_result = saved_result
                        st.session_state.admin_result_review = saved_result
                        st.session_state.studio_state = updated
                        service.give_feedback(approved_turn, rating, correction,
                                              data_dir=studio.DATA, db_path=studio.DB)
                        st.success('Response approved and trainer feedback saved locally.')
                        st.rerun()
                    except (ModelError, ModelOutputError, ValueError):
                        st.error('Approval or feedback could not be saved. No success is claimed.')
                    except Exception:
                        st.error('Approval or feedback could not be saved. No success is claimed.')
                elif st.session_state.studio_last_turn is not None:
                    try:
                        service.give_feedback(st.session_state.studio_last_turn, rating, correction,
                                              data_dir=studio.DATA, db_path=studio.DB)
                        st.success('Trainer rating and correction saved locally.')
                        st.rerun()
                    except ValueError:
                        st.error('Trainer feedback could not be saved.')
                else:
                    st.warning('This result has no saved training turn to rate.')


def _save_response(session_id, text, message_type, status='not_applicable', *, lesson_id=None):
    conversation.save_message(session_id, 'assistant', text, message_type=message_type,
                              inference_status=status, related_lesson_id=lesson_id,
                              data_dir=studio.DATA, db_path=studio.DB)


def _lesson_editor(message, pending):
    record = pending['record']
    st.info("I've prepared a lesson from your instructions. Please review it before approving.")
    with st.expander('Review and edit lesson proposal', expanded=True):
        st.caption('Proposed only. Preview does not call the model or save learning.')
        st.caption('Edit the fields below before choosing Approve or Reject.')
        record['scenario_summary'] = st.text_area('Scenario summary', record['scenario_summary'], key=f"edit_scenario_{message['message_id']}")
        record['corrective_principle'] = st.text_area('Corrective principle', record['corrective_principle'], key=f"edit_principle_{message['message_id']}")
        for field, label in (('emotional_context', 'Emotional context'), ('observed_facts', 'Observed facts'), ('assumptions_or_uncertainties', 'Assumptions or uncertainties'), ('recommended_response_pattern', 'Recommended response pattern'), ('relationship_context', 'Relationship context')):
            record[field] = st.text_area(label, record[field], key=f"edit_{field}_{message['message_id']}")
        approve_col, reject_col = st.columns(2)
        if approve_col.button('Approve lesson', key=f"approve_{message['message_id']}"):
            try:
                lesson_id = lessons.approve(record, data_dir=studio.DATA, db_path=studio.DB)
                _save_response(st.session_state.conversation_id,
                               'Lesson approved and saved. It may now be retrieved when relevant.',
                               'lesson_approved', lesson_id=lesson_id)
                st.session_state.pending_lesson = None
                conversation.save_lesson_state(st.session_state.conversation_id, None,
                                               data_dir=studio.DATA, db_path=studio.DB)
                st.rerun()
            except (ValueError, OSError):
                st.error('The lesson could not be saved. No approval is claimed.')
        if reject_col.button('Reject lesson', key=f"reject_{message['message_id']}"):
            _save_response(st.session_state.conversation_id,
                           'Proposal rejected and discarded; no approved lesson was saved.', 'lesson_rejected')
            st.session_state.pending_lesson = None
            conversation.save_lesson_state(st.session_state.conversation_id, None,
                                           data_dir=studio.DATA, db_path=studio.DB)
            st.rerun()


def _handle_message(user_text, session_id, history_messages, profile, model_config, configuration_error):
    route = conversation.classify_intent(user_text)
    persisted_pending = conversation.load_lesson_state(session_id, data_dir=studio.DATA, db_path=studio.DB)
    # Never let an incomplete draft capture a separate request. Only an explicit
    # training signal (or a labeled field update) continues the workflow.
    fields_in_message = conversation.extract_lesson_fields(user_text)
    if (persisted_pending and persisted_pending.get('status') == 'incomplete'
            and route.intent == 'training' and not fields_in_message
            and re.search(r'\b(continue|resume|teach|training|lesson|draft)\b', user_text, re.I)):
        route = conversation.Route('training_follow_up', 'contextual',
                                   'Explicit training continuation for the active conversation draft.')
    conversation.save_message(session_id, 'user', user_text, message_type=route.intent,
                              data_dir=studio.DATA, db_path=studio.DB)
    if route.intent == 'training_cancel':
        if persisted_pending and persisted_pending.get('status') == 'incomplete':
            _save_response(session_id, 'Understood. The incomplete training draft is canceled.', 'training_canceled')
            conversation.save_lesson_state(session_id, None, data_dir=studio.DATA, db_path=studio.DB)
            if st.session_state.get('pending_lesson', {}).get('conversation_id') == session_id:
                st.session_state.pending_lesson = None
        elif persisted_pending and persisted_pending.get('status') == 'proposed':
            _save_response(session_id, 'A lesson proposal is awaiting review. Use Reject lesson to explicitly reject it.', 'lesson_status')
        else:
            _save_response(session_id, 'There is no pending training draft to cancel.', 'lesson_status')
        return
    if route.intent == 'training_resume':
        pending = persisted_pending
        if pending and pending.get('status') == 'incomplete':
            st.session_state.pending_lesson = pending
            missing = conversation.missing_lesson_fields(pending.get('fields', {}))
            _save_response(session_id, 'Training draft resumed. Please provide these missing fields: ' +
                           ', '.join(missing) + '.', 'lesson_clarification')
        elif pending and pending.get('status') == 'proposed':
            st.session_state.pending_lesson = pending
            _save_response(session_id, 'Your lesson proposal is ready to review in this conversation.', 'lesson_status')
        else:
            _save_response(session_id, 'There is no pending training draft to resume. You can start one by saying you want to teach a lesson.', 'lesson_status')
        return
    if route.intent in ('training', 'training_follow_up', 'correction'):
        pending = st.session_state.get('pending_lesson')
        if not pending or pending.get('conversation_id') != session_id:
            pending = conversation.load_lesson_state(session_id, data_dir=studio.DATA, db_path=studio.DB)
        if pending and pending.get('status') == 'proposed' and route.intent in ('training', 'correction'):
            # The same submitted text is already represented in this chat; keep one proposal only.
            prior_submission = any(m['role'] == 'user' and m['content'] == user_text and
                                   m['message_type'] in ('training', 'correction') for m in history_messages)
            if prior_submission:
                st.session_state.pending_lesson = pending
                return
        fields = conversation.extract_lesson_fields(user_text)
        pending_followup_fields = None
        if pending and pending.get('status') == 'incomplete' and route.intent in ('training', 'training_follow_up') and not fields:
            merged = dict(pending.get('fields', {}))
            if user_text.strip():
                missing = conversation.missing_lesson_fields(merged)
                if len(missing) == 1:
                    merged['corrective_principle'] = user_text.strip()
                else:
                    _save_response(session_id, 'Please provide only these missing fields: ' + ', '.join(missing) + '.', 'lesson_clarification')
                    return
            pending_followup_fields = merged
        if route.intent == 'training' and not fields and (not pending or pending.get('status') != 'incomplete'):
            state = {'fields': {}, 'message_id': str(uuid.uuid4()),
                     'conversation_id': session_id, 'status': 'incomplete'}
            st.session_state.pending_lesson = state
            conversation.save_lesson_state(session_id, state, data_dir=studio.DATA, db_path=studio.DB)
            _save_response(session_id, 'Please provide the lesson fields you want to teach. I will not invent missing details.', 'lesson_clarification')
            return
        if pending and pending.get('status') == 'proposed' and route.intent in ('training', 'training_follow_up') and not fields:
            _save_response(session_id, 'Your lesson proposal is still pending. Edit it below, or explicitly approve or reject it.', 'lesson_status')
            return
        if route.intent == 'correction' and pending:
            merged = dict(pending.get('fields', {}))
            if fields:
                merged.update(fields)
            else:
                merged['corrective_principle'] = user_text
        elif pending_followup_fields is not None:
            merged = pending_followup_fields
        elif pending and pending.get('status') == 'incomplete' and route.intent in ('training', 'training_follow_up'):
            merged = dict(pending.get('fields', {}))
            merged.update(fields)
            if not fields:
                _save_response(session_id, 'Please provide only these missing fields: ' + ', '.join(
                    conversation.missing_lesson_fields(merged)) + '.', 'lesson_clarification')
                return
        else:
            merged = fields
        proposal, merged = conversation.prepare_lesson('', existing=merged)
        if proposal:
            previous = next((m for m in reversed(history_messages)
                             if m['role'] == 'assistant' and m['message_type'] == 'validated_reasoning'), None)
            if route.intent == 'correction' and previous:
                proposal['source_provenance'] = 'trainer_correction:' + previous['message_id']
            reuse = pending and pending.get('status') == 'proposed' and pending.get('conversation_id') == session_id
            assistant_id = pending['message_id'] if reuse else str(uuid.uuid4())
            if reuse:
                proposal['lesson_id'] = pending['record']['lesson_id']
                proposal['created_at'] = pending['record']['created_at']
            current = {'record': proposal, 'fields': merged, 'message_id': assistant_id,
                       'conversation_id': session_id, 'status': 'proposed'}
            st.session_state.pending_lesson = current
            conversation.save_lesson_state(session_id, current, data_dir=studio.DATA, db_path=studio.DB)
            conversation.save_message(session_id, 'assistant',
                                      "I've prepared a lesson from your instructions. Please review it before approving.",
                                      message_id=assistant_id, message_type='lesson_proposal',
                                      data_dir=studio.DATA, db_path=studio.DB)
        else:
            missing = conversation.missing_lesson_fields(merged)
            previous_state = pending if pending and pending.get('status') == 'incomplete' else None
            state = {'fields': merged,
                     'message_id': previous_state.get('message_id') if previous_state else str(uuid.uuid4()),
                     'conversation_id': session_id, 'status': 'incomplete'}
            st.session_state.pending_lesson = state
            conversation.save_lesson_state(session_id, state, data_dir=studio.DATA, db_path=studio.DB)
            _save_response(session_id, 'Please provide only these missing fields: ' + ', '.join(missing) +
                           '. You may use the field labels.', 'lesson_clarification')
        return
    if route.intent in ('lesson_approval', 'lesson_rejection'):
        pending = st.session_state.get('pending_lesson')
        if not pending or pending.get('conversation_id') != session_id:
            pending = conversation.load_lesson_state(session_id, data_dir=studio.DATA, db_path=studio.DB)
        if not pending or pending.get('status') != 'proposed':
            _save_response(session_id, 'There is no complete lesson proposal to ' +
                           ('approve.' if route.intent == 'lesson_approval' else 'reject.'), 'lesson_clarification')
        elif route.intent == 'lesson_approval':
            lesson_id = lessons.approve(pending['record'], data_dir=studio.DATA, db_path=studio.DB)
            _save_response(session_id, 'Lesson approved and saved.', 'lesson_approved', lesson_id=lesson_id)
            conversation.save_lesson_state(session_id, None, data_dir=studio.DATA, db_path=studio.DB)
            if st.session_state.get('pending_lesson', {}).get('conversation_id') == session_id:
                st.session_state.pending_lesson = None
        else:
            _save_response(session_id, 'Proposal rejected and discarded; no approved lesson was saved.', 'lesson_rejected')
            conversation.save_lesson_state(session_id, None, data_dir=studio.DATA, db_path=studio.DB)
            if st.session_state.get('pending_lesson', {}).get('conversation_id') == session_id:
                st.session_state.pending_lesson = None
        return
    if route.intent == 'memory_recall':
        found = lessons.retrieve(user_text, data_dir=studio.DATA, db_path=studio.DB)
        if found:
            text = 'Approved lessons matching your wording:\n' + '\n'.join(
                f"- {item['corrective_principle']} (lesson ID: {item['lesson_id']}; source: {item['source_type']}; matched terms: {', '.join(item['relevance']['matched_terms'])})"
                for item in found)
            _save_response(session_id, text, 'memory_recall')
        else:
            approved = lessons.list_lessons(data_dir=studio.DATA, db_path=studio.DB)
            # A broad request such as 'what do you remember about rejection?' may
            # use wording absent from the record. Return inspectable candidates
            # rather than falling through to reasoning or treating it as training.
            text = ('No lesson matched those exact terms. Current approved lesson summaries:\n' +
                    '\n'.join(f"- {item['scenario_summary']} (lesson ID: {item['lesson_id']}; source: {item['source_type']})"
                               for item in approved)) if approved else 'There are no approved lessons to retrieve.'
            _save_response(session_id, text, 'memory_empty')
        return
    if route.intent == 'general':
        _save_response(session_id, conversation.respond_general(user_text, profile), 'deterministic_response')
        return
    if route.intent != 'emotional_reasoning':
        _save_response(session_id, 'I am not sure how to route that request. Could you clarify whether you want to chat, consider a situation, teach a principle, or recall an approved lesson?', 'clarification')
        return
    try:
        with st.status('Considering your message…', expanded=False):
            reasoning_context = service.cognition.assess(user_text, profile, {'emotions': dict(NEUTRAL)})
            # Conversation reasoning uses the approved-memory setting, currently enabled
            # for trainer corrections. Recalled lessons are context, not current facts.
            approved_lessons = lessons.retrieve(user_text, limit=3,
                                                data_dir=studio.DATA, db_path=studio.DB)
            reasoning_context['supervised_lessons'] = approved_lessons
            reasoning_context['supervised_lessons_enabled'] = True
            reasoning_context['retrieved_lessons_context_only'] = True
            reasoning_context['memory_provenance_guidance'] = (
                'Retrieved approved lessons are prior trainer-authored context only. Preserve lesson IDs and sources; '
                'do not treat a lesson as verified evidence about the current situation.')
            result = trainer.infer(user_text, '', {'emotions': dict(NEUTRAL)}, {}, config=model_config,
                                   cognitive_context=reasoning_context, persistent_profile=profile)
        if result.get('_trainer_pending') or result.get('_trainer_approved'):
            _save_response(session_id,
                           'The reasoning pathway returned a training-review result, not a validated conversational analysis. No decision or state change is claimed.',
                           'reasoning_failure', 'failed')
            return
        _save_response(session_id, result.get('conversational_response', result['narrative']),
                       'validated_reasoning', 'validated')
    except ModelOutputError as error:
        stage = getattr(error, 'stage', None) or 'reasoning pipeline'
        category = getattr(error, 'criterion', None) or 'structured_or_cognitive_validation'
        safe = f"Reasoning stopped at {stage}; category: {category[:120]}. Your message is preserved; no interpretation is claimed."
        _save_response(session_id, safe, 'reasoning_failure', 'failed')
        st.session_state.chat_error = safe
        if model_config is not None and model_config.local:
            _offer_cloud_fallback(user_text, session_id, profile,
                reasoning_context.get('supervised_lessons', []), local_error=error)
    except ModelError as error:
        from brain_core.providers import category_for_error
        safe = f"Local inference is unavailable ({category_for_error(error)}). Your message is preserved. No cloud request was sent."
        _save_response(session_id, safe, 'reasoning_failure', 'unavailable')
        st.session_state.chat_error = safe
        if model_config is not None and model_config.local:
            _offer_cloud_fallback(user_text, session_id, profile,
                reasoning_context.get('supervised_lessons', []), local_error=error)
    except Exception:
        _save_response(session_id, 'Reasoning stopped because of an internal error. Your message is preserved; no interpretation is claimed.', 'reasoning_failure', 'failed')
        st.session_state.chat_error = 'Reasoning stopped because of an internal error. Your message is preserved; no interpretation is claimed.'


def render_conversation(profile, ready, model_config, configuration_error):
    chat_error = st.session_state.get('chat_error')
    if chat_error:
        st.warning(chat_error)
        del st.session_state['chat_error']
    st.subheader('Talk with Sovereign Brain')
    st.caption(f"{profile.get('identity_name', 'Sovereign Brain')} · Local chat history · Lessons require your approval")
    sessions = conversation.list_sessions(data_dir=studio.DATA, db_path=studio.DB)
    if 'conversation_id' not in st.session_state or not any(s['conversation_id'] == st.session_state.conversation_id for s in sessions):
        st.session_state.conversation_id = sessions[0]['conversation_id'] if sessions else conversation.create_session(data_dir=studio.DATA, db_path=studio.DB)
    if ('pending_lesson' not in st.session_state or
            st.session_state.get('pending_lesson') is None or
            st.session_state.pending_lesson.get('conversation_id') != st.session_state.conversation_id):
        st.session_state.pending_lesson = conversation.load_lesson_state(
            st.session_state.conversation_id, data_dir=studio.DATA, db_path=studio.DB)
    with st.sidebar:
        st.subheader('Conversations')
        def select_conversation():
            st.session_state.conversation_id = st.session_state.conversation_selector
            st.session_state.pending_lesson = conversation.load_lesson_state(
                st.session_state.conversation_id, data_dir=studio.DATA, db_path=studio.DB)

        if st.button('＋ New conversation'):
            st.session_state.conversation_id = conversation.create_session(data_dir=studio.DATA, db_path=studio.DB)
            st.session_state.pending_lesson = conversation.load_lesson_state(
                st.session_state.conversation_id, data_dir=studio.DATA, db_path=studio.DB)
            st.rerun()
        active_draft = conversation.load_lesson_state(st.session_state.conversation_id,
                                                       data_dir=studio.DATA, db_path=studio.DB)
        if active_draft and active_draft.get('status') == 'incomplete':
            st.caption('An incomplete training draft is saved in this conversation.')
            resume_col, cancel_col = st.columns(2)
            if resume_col.button('Resume training draft', key=f"resume_draft_{st.session_state.conversation_id}"):
                st.session_state.pending_lesson = active_draft
                _save_response(st.session_state.conversation_id,
                               'Training draft resumed. Provide labeled missing fields to continue.',
                               'lesson_status')
                st.rerun()
            if cancel_col.button('Cancel training draft', key=f"cancel_draft_{st.session_state.conversation_id}"):
                conversation.save_lesson_state(st.session_state.conversation_id, None,
                                               data_dir=studio.DATA, db_path=studio.DB)
                st.session_state.pending_lesson = None
                _save_response(st.session_state.conversation_id,
                               'The incomplete training draft was canceled.', 'training_canceled')
                st.rerun()
        sessions = conversation.list_sessions(data_dir=studio.DATA, db_path=studio.DB)
        if sessions:
            st.selectbox('Conversation', [item['conversation_id'] for item in sessions],
                         index=next((i for i, item in enumerate(sessions) if item['conversation_id'] == st.session_state.conversation_id), 0),
                         format_func=lambda item_id: next(item['title'] for item in sessions if item['conversation_id'] == item_id),
                         key='conversation_selector', on_change=select_conversation)
        with st.popover('Delete current conversation'):
            st.warning('Chat messages only will be deleted. Approved lessons remain.')
            if st.button('Confirm conversation deletion', key='confirm_delete_chat'):
                conversation.delete_session(st.session_state.conversation_id, confirmed=True,
                                            data_dir=studio.DATA, db_path=studio.DB)
                st.session_state.conversation_id = conversation.create_session(data_dir=studio.DATA, db_path=studio.DB)
                st.session_state.pending_lesson = None
                conversation.save_lesson_state(session_id, None, data_dir=studio.DATA, db_path=studio.DB)
                st.session_state.conversation_selector = st.session_state.conversation_id
                st.rerun()
    session_id = st.session_state.conversation_id
    st.caption('Model: ' + ('available' if ready else 'not available; lessons and recall remain available'))
    history = conversation.load_messages(session_id, data_dir=studio.DATA, db_path=studio.DB)
    for item in history:
        with st.chat_message(item['role']):
            st.markdown(item['content'])
            pending = st.session_state.get('pending_lesson')
            if item['message_type'] == 'lesson_proposal' and pending and pending.get('message_id') == item['message_id'] and pending.get('conversation_id') == session_id:
                _lesson_editor(item, pending)
    user_text = st.chat_input('Message Sovereign Brain…', max_chars=8000)
    if user_text:
        _handle_message(user_text, session_id, history, profile, model_config, configuration_error)
        st.rerun()
    _render_cloud_approval(session_id)


def render_admin(profile, mode, remote_authorized, model, ready, configuration_error):
    st.subheader('Administrator tools')
    st.caption('Local technical and memory tools. This section is not authentication; keep access bound to loopback.')
    state, history = trainer.inspect_status()
    if state is None:
        state = {'iterations': 0, 'emotion': 'neutral', 'metrics': dict(trainer.BASE), 'emotions': dict(NEUTRAL)}
    with st.expander('Model settings and system health'):
        cloud = alibaba_configuration()
        st.write('Cloud Qwen: approval required for every inference · API key configured:', cloud.api_key_configured)
        if cloud.errors:
            st.caption('Cloud configuration incomplete: ' + ' '.join(cloud.errors))
        st.write('Alibaba region:', cloud.region or 'not configured', '· workspace configured:', bool(cloud.workspace_id),
                 '· endpoint configured:', bool(cloud.endpoint), '· selected model:', cloud.model or 'not configured')
        st.caption('Configuration presence is not proof of API callability. No health-check inference is sent.')
        st.write('Configured model:', model, '· detected:', ready)
        st.write('Inference selection:', mode, '· remote authorization:', remote_authorized)
        st.write('Inference status:', configuration_error or 'Ready subject to per-request validation.')
        st.write('Local Ollama installed models:', ', '.join(installed_models()) or 'not detected')
        st.write('Available RAM (GiB):', available_memory_gib())
        st.write('Saved turns:', len(studio.inspect_turns(1000)))
        st.write('Persistent identity:', profile.get('identity_name'), profile.get('identity_id'))
        if st.button('Refresh model status', key='admin_refresh_models'):
            installed_models.clear()
            st.rerun()
    with st.expander('Emotional-state inspection'):
        st.json(state)
        st.caption('Read-only inspection; chat does not modify simulated emotion.')
    with st.expander('Approved lessons and audit log'):
        for item in lessons.list_lessons(data_dir=studio.DATA, db_path=studio.DB, include_revoked=True):
            st.write(item['lesson_id'], item['approval_status'], item['scenario_summary'])
            st.write(item['corrective_principle'])
            st.json(lessons.audit_events(item['lesson_id'], data_dir=studio.DATA, db_path=studio.DB))
            if item['approval_status'] == 'approved' and st.button('Revoke lesson', key=f"admin_revoke_{item['lesson_id']}"):
                lessons.revoke(item['lesson_id'], data_dir=studio.DATA, db_path=studio.DB)
                st.rerun()
    with st.expander('Training history and legacy rules'):
        for row in studio.inspect_turns(50):
            st.write(f"#{row['id']} · {row['created']} · {row['rating'] or 'unrated'}")
            st.write(row['scenario'])
            st.write(row['commentary'] or row['feedback'] or 'No correction')
    with st.expander('Documents and approved research'):
        st.json(studio.inspect_documents())
        st.json(studio.inspect_research_items())
        uploads = st.file_uploader('Import reference documents', type=['pdf', 'docx', 'txt', 'md'], accept_multiple_files=True)
        if st.button('Import uploaded documents', disabled=not uploads):
            for upload in uploads:
                try:
                    studio.add_document(upload.name, studio.decode_document(upload.name, upload.getvalue()))
                except Exception:
                    st.warning('Document import failed. Check type, size and readable text.')
        with st.form('admin_research'):
            topic = st.text_input('Research question', max_chars=500)
            search = st.form_submit_button('Find evidence')
        if search and topic.strip():
            try:
                st.write(studio.research_search(topic))
            except Exception:
                st.warning('Research unavailable; check the optional local research configuration.')
        for item in studio.inspect_research_items():
            with st.expander(item['title'] or item['url']):
                st.write(item['url'], item['excerpt'])
                approved = st.checkbox('Approve as reference evidence', value=bool(item['approved']), key=f"research_{item['id']}")
                if st.button('Save research approval', key=f"approve_research_{item['id']}"):
                    studio.approve_research(item['id'], bool(approved))
                    st.rerun()
    with st.expander('Cognitive diagnostics'):
        diagnostic_dir = os.environ.get('BRAIN_DIAGNOSTIC_DIR')
        if diagnostic_dir and Path(diagnostic_dir).is_dir():
            for path in sorted(Path(diagnostic_dir).glob('*.json'))[-20:]:
                try:
                    st.json(json.loads(path.read_text(encoding='utf-8')))
                except Exception:
                    st.caption('A diagnostic record could not be read.')
        else:
            st.caption('No configured local diagnostic directory was found.')
    with st.expander('Legacy trainer workflow', expanded=False):
        st.session_state.setdefault('admin_result_review', None)
        scenario = st.text_area('Situation', height=135, max_chars=8000)
        context = st.text_area('Context and relationships (optional)', height=80, max_chars=3000)
        label = st.text_input('Relationship or context label (optional)', max_chars=100)
        guidance = st.text_area('Trainer guidance (optional)', height=75, max_chars=4000)
        use_memory = st.checkbox('Retrieve previous trainer corrections', value=True)
        use_refs = st.checkbox('Use uploaded documents and approved research', value=False)
        combined = scenario.strip() + ('\n\nContext and relationships: ' + context.strip() if context.strip() else '')
        retry_pending = st.session_state.get('admin_retry_pending', False)
        if st.button('Analyze emotions and decide', type='primary', key='admin_analyze', disabled=not scenario.strip() or bool(configuration_error)) or retry_pending:
            st.session_state.admin_retry_pending = False
            try:
                with st.spinner('Analyzing locally...'):
                    turn_id, updated, result, retrieved = service.analyze(
                        combined, guidance, mock=(mode == 'Offline demonstration'),
                        config=ModelConfig(model=model) if mode == 'Local model (Ollama)' else None,
                        use_references=use_refs, use_feedback=use_memory, relationship_label=label,
                        state_path=trainer.STATE_PATH, history_path=trainer.HISTORY_PATH,
                        data_dir=studio.DATA, db_path=studio.DB, profile_path=personality.PROFILE_PATH,
                        persist_fixture_state=(mode == 'Offline demonstration'))
                st.session_state.studio_last_turn = turn_id
                st.session_state.studio_result = result
                st.session_state.admin_result_review = result
                st.session_state.studio_state = updated
                st.session_state.studio_feedback = retrieved
                st.rerun()
            except ModelOutputError as error:
                st.error('The model response did not meet reasoning quality checks. No training or emotional state was changed.')
                if error.diagnostic_id:
                    st.caption(f'Diagnostic reference: {error.diagnostic_id}')
                if st.button('Retry analysis', key='admin_retry_analysis'):
                    st.session_state.admin_retry_pending = True
                    st.rerun()
            except (ModelError, ValueError):
                st.error('Analysis failed or was unavailable. No result is claimed.')
        if st.session_state.get('admin_result_review') is not None:
            result = st.session_state.admin_result_review
            provenance = result.get('_provenance', {})
            st.subheader('Decision review')
            st.caption(f"Source: {provenance.get('source', 'unknown')} · Model: {provenance.get('model', 'not recorded')}")
            st.write(result.get('narrative', 'No narrative available.'))
            decision = result.get('decision', {})
            if decision:
                left, right = st.columns(2)
                with left:
                    st.markdown('**Competing emotions**')
                    for emotion in decision.get('conflicting_emotions', []):
                        st.write('• ' + emotion)
                    st.markdown('**Evidence and uncertainty**')
                    st.write(decision.get('evidence', ''))
                    st.write(decision.get('uncertainty', ''))
                with right:
                    st.markdown('**Options considered**')
                    for option in decision.get('options', []):
                        st.write('• ' + option)
                    st.markdown('**Proposed decision and rationale**')
                    st.write(decision.get('recommended_action', ''))
                    st.write(decision.get('rationale', ''))
            transition = emotional_transition(result, st.session_state.get('studio_state') or state)
            try:
                st.bar_chart(transition, x='Emotion', y=['Before', 'After'], horizontal=True, stack=False)
                st.dataframe(transition, hide_index=True, width='stretch')
            except (ImportError, ModuleNotFoundError):
                st.json(transition)
            st.json(result.get('_cognitive_context', {}))
            if result.get('_trainer_pending'):
                st.warning('This decision is pending explicit approval. No learning or simulated state update is committed yet.')
            rating = st.radio('Rate emotional appropriateness', ['good', 'partial', 'poor'], horizontal=True,
                              key=f"admin_rating_{st.session_state.studio_last_turn}")
            correction = st.text_area('Correct the response / challenge its recommendation', max_chars=4000,
                                      key=f"admin_correction_{st.session_state.studio_last_turn}")
            if st.button('Save trainer feedback', key='admin_save_feedback'):
                if provenance.get('source') == 'offline_fixture':
                    st.warning('Offline demonstration fixtures cannot be approved as training.')
                elif result.get('_trainer_pending'):
                    approved_result = dict(result, _trainer_approved=True)
                    approved_result.pop('_trainer_pending', None)
                    approved_result['_provenance'] = dict(provenance, source='approved_training')
                    try:
                        approved_turn, updated, saved_result, _ = service.analyze(
                            combined, guidance, config=ModelConfig(model=model) if mode == 'Local model (Ollama)' else None,
                            use_references=use_refs, use_feedback=use_memory, relationship_label=label,
                            state_path=trainer.STATE_PATH, history_path=trainer.HISTORY_PATH,
                            data_dir=studio.DATA, db_path=studio.DB, profile_path=personality.PROFILE_PATH,
                            approved_result=approved_result)
                        approved_turn = approved_turn or st.session_state.studio_last_turn
                        st.session_state.studio_last_turn = approved_turn
                        st.session_state.studio_result = saved_result
                        st.session_state.admin_result_review = saved_result
                        st.session_state.studio_state = updated
                        service.give_feedback(approved_turn, rating, correction,
                                              data_dir=studio.DATA, db_path=studio.DB)
                        st.success('Response approved and trainer feedback saved locally.')
                        st.rerun()
                    except (ModelError, ModelOutputError, ValueError):
                        st.error('Approval or feedback could not be saved. No success is claimed.')
                    except Exception:
                        st.error('Approval or feedback could not be saved. No success is claimed.')
                elif st.session_state.studio_last_turn is not None:
                    try:
                        service.give_feedback(st.session_state.studio_last_turn, rating, correction,
                                              data_dir=studio.DATA, db_path=studio.DB)
                        st.success('Trainer rating and correction saved locally.')
                        st.rerun()
                    except ValueError:
                        st.error('Trainer feedback could not be saved.')
                else:
                    st.warning('This result has no saved training turn to rate.')


mode, remote_authorized, local_model, ready, config, configuration_error = _model_configuration()
page = st.session_state.get('workspace_page', 'Conversation')
with st.sidebar:
    state, history = trainer.inspect_status()
    if state is None:
        state = {'iterations': 0, 'emotion': 'neutral', 'metrics': dict(trainer.BASE), 'emotions': dict(NEUTRAL)}
    st.metric('Training iterations', state['iterations'])
    st.caption('Local records are not encrypted. Keep this service on loopback.')

if page == 'Conversation':
    render_conversation(profile, ready, config, configuration_error)
else:
    render_admin(profile, mode, remote_authorized, local_model, ready, configuration_error)
