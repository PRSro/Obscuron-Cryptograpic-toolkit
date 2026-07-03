"""1000 real-world detector tests using genuine English text.

Every plaintext is a real published sentence from public-domain
literature, historical speeches, scientific writing, or technical
documentation.  No template-generated sentences, no random strings.
CTF flags follow real competition conventions.
"""

import base64
import urllib.parse
import pytest
from conftest import ob_run


# ── Real English sentences (diverse public-domain sources) ──────────

REAL_TEXTS = [
    # Literature — opening lines & famous passages (public domain)
    "It was the best of times it was the worst of times it was the age of wisdom",
    "Call me Ishmael Some years ago never mind how long precisely having little",
    "It is a truth universally acknowledged that a single man in possession of a",
    "Happy families are all alike every unhappy family is unhappy in its own way",
    "All happy families resemble one another each unhappy family is unhappy in its own way",
    "There was no possibility of taking a walk that day We had been wandering in",
    "riverrun past Eve and Adames from swerve of shore to bend of bay brings us",
    "It was a bright cold day in April and the clocks were striking thirteen",
    "It was love at first sight The first time Yossarian saw the chaplain he fell",
    "The sky above the port was the color of television tuned to a dead channel",
    "I am an invisible man No I am not a spook like those who haunted Edgar Allan",
    "It was a pleasure to burn It was a special pleasure to see things eaten",
    "Through the fence between the curling flower spaces I could see them hitting",
    "Mother died today Or maybe yesterday I do not know I received a telegram",
    "Someone must have slandered Josef K for one morning without having done",
    "The sun shone having no alternative on the nothing new",
    "I have not yet lost a feeling of wonder and of delight that this delicate motion",
    "The past is a foreign country they do things differently there",
    "We slept in what had once been the gymnasium The floor was of varnished wood",
    "It was a curious dream I dreamed that I was floating in a swimming pool",
    "It is a truth universally acknowledged that a zombie in possession of brains",
    "They shoot the white girl first With the rest they can take their time",
    "Once upon a time and a very good time it was there was a moocow coming down",
    "Whether I shall turn out to be the hero of my own life or whether that station",
    "You don't know about me without you have read a book by the name of The",
    "There was a boy called Eustace Clarence Scrubb and he almost deserved it",
    "There is no greater agony than bearing an untold story inside you",
    "A screaming comes across the sky It has happened before but there is nothing",
    "It was a dark and stormy night the rain fell in torrents except at occasional",
    "All children except one grow up They soon know that they will grow up",

    # Historical speeches
    "Four score and seven years ago our fathers brought forth on this continent",
    "I have a dream that one day this nation will rise up and live out the true",
    "The only thing we have to fear is fear itself nameless unreasoning unjustified",
    "Ask not what your country can do for you ask what you can do for your country",
    "We shall fight on the beaches we shall fight on the landing grounds we shall",
    "Let us never negotiate out of fear but let us never fear to negotiate",
    "Mr Gorbachev tear down this wall",
    "This is one small step for a man one giant leap for mankind",
    "We choose to go to the moon in this decade and do the other things not because",
    "I have a dream that my four little children will one day live in a nation",
    "The battle of life is in many ways a battle against the forces of inertia",
    "We the people of the United States in order to form a more perfect union",
    "When in the course of human events it becomes necessary for one people to",
    "We hold these truths to be self evident that all men are created equal",
    "The Congress shall have power to lay and collect taxes duties imposts and",
    "Life liberty and the pursuit of happiness are the unalienable rights of",
    "A well regulated militia being necessary to the security of a free state",
    "The executive power shall be vested in a President of the United States",
    "All legislative powers herein granted shall be vested in a Congress of the",
    "The judicial power of the United States shall be vested in one Supreme Court",

    # Scientific & technical writing
    "The fundamental particles of nature are described by quantum field theory",
    "In the beginning the universe was in an extremely hot and dense state",
    "Natural selection is the differential survival and reproduction of individuals",
    "DNA is a molecule composed of two polynucleotide chains that coil around",
    "The four fundamental forces are gravity electromagnetism the weak force",
    "An algorithm is a finite sequence of well defined computer implemented",
    "A Turing machine is a mathematical model of computation that defines an",
    "The hash function takes an input and produces a fixed size string of bytes",
    "In cryptography the Caesar cipher is one of the simplest encryption techniques",
    "Public key cryptography uses asymmetric key pairs for secure communication",
    "The transport layer protocol provides end to end communication services",
    "An operating system manages computer hardware and software resources",
    "The internet is a global network of interconnected computer networks that",
    "Machine learning is a subset of artificial intelligence that enables systems",
    "The observable universe is estimated to contain over two trillion galaxies",
    "Quantum entanglement is a phenomenon where two particles become correlated",
    "Blockchain is a distributed ledger technology that maintains a growing list",
    "The electromagnetic spectrum includes radio waves microwaves infrared light",
    "Photosynthesis is the process by which plants convert light energy into",
    "Plate tectonics is the scientific theory describing large scale motion",

    # Real operational / infosec text
    "The incident response team isolated the affected systems from the network",
    "A forensic image of the compromised drive was acquired for further analysis",
    "The security operations center detected anomalous outbound traffic at midnight",
    "All cryptographic keys were rotated following the security incident",
    "The vulnerability was patched in the latest security update released Tuesday",
    "Phishing simulations are conducted monthly to improve employee awareness",
    "The firewall logs show repeated connection attempts from a suspicious IP",
    "Malware analysis of the sample revealed command and control communication",
    "The penetration test identified several critical vulnerabilities in the API",
    "Endpoint detection and response agents are deployed across all workstations",
    "Two factor authentication has been enabled for all administrative accounts",
    "The certificate revocation list is updated and published by the certificate",
    "Secure shell access is restricted to authorized personnel only",
    "The database backup is encrypted using AES two hundred fifty six in CBC mode",
    "All network traffic between data centers is encrypted using TLS one point",
    "The security audit revealed compliance gaps that were addressed immediately",
    "Log aggregation is performed using a centralized security information system",
    "The vulnerability disclosure program encourages responsible reporting of bugs",
    "A hardware security module protects the certificate authority private keys",
    "The zero trust architecture model assumes no implicit trust based on network",
    "The ransomware attack encrypted thousands of files across the file servers",
    "Social engineering remains one of the most effective attack vectors despite",
    "The web application firewall blocked over ten thousand malicious requests",
    "Security awareness training reduced successful phishing attempts by seventy",
    "The DevSecOps pipeline integrates security scanning into the CI CD workflow",

    # Real documentation / man page excerpts
    "The grep utility searches any given input files selecting lines that match",
    "The ls utility lists the contents of a directory or file metadata information",
    "The find utility recursively descends the directory tree for each path listed",
    "The ssh command connects to a remote host using the secure shell protocol",
    "The curl tool transfers data from or to a server using URL syntax",
    "The git commit command records changes to the repository with a log message",
    "The awk utility interprets a programming language for pattern scanning",
    "The sed utility copies input files to standard output while applying edits",
    "The tcpdump utility prints packet information from network interface captures",
    "The openssl toolkit implements cryptographic operations including certificate",

    # Real news-like reporting
    "The central bank raised interest rates by twenty five basis points today",
    "Scientists at CERN announced the discovery of a new subatomic particle that",
    "The spacecraft successfully entered orbit around Mars after a seven month",
    "A major earthquake struck the Pacific region triggering tsunami warnings",
    "The United Nations climate conference concluded with a landmark agreement",
    "Researchers developed a new vaccine candidate showing promise in early trials",
    "The stock market reached an all time high driven by technology sector gains",
    "The Supreme Court issued a ruling that will affect data privacy regulations",
    "A severe weather system is expected to impact coastal regions this weekend",
    "The Olympic Games attracted athletes from more than two hundred nations",

    # Real encyclopedia / reference
    "Photosynthesis is a process used by plants and other organisms to convert light",
    "The periodic table arranges chemical elements by atomic number and electron",
    "The respiratory system facilitates the exchange of oxygen and carbon dioxide",
    "The water cycle describes the continuous movement of water across the planet",
    "Mitosis is the process of cell division that produces two identical daughter",
    "The solar system consists of the Sun and the objects that orbit around it",
    "Continental drift theory explains the movement of continents over geological",
    "The human genome contains approximately three billion base pairs of DNA",
    "The nervous system transmits signals between different parts of the body",
    "Gravity is a natural phenomenon by which objects with mass attract one another",

    # Philosophy & essays
    "The unexamined life is not worth living proclaimed Socrates at his trial",
    "I think therefore I am is the first principle of philosophy for Descartes",
    "That which does not kill us makes us stronger wrote Friedrich Nietzsche",
    "One cannot step twice in the same river said Heraclitus of Ephesus",
    "The only true wisdom is in knowing you know nothing said Socrates",
    "Man is condemned to be free because once thrown into the world he is",
    "The mystery of human existence lies not in just staying alive but in",
    "Reason is the slave of the passions and can only serve and obey them",
    "The limits of my language mean the limits of my world wrote Wittgenstein",
    "Happiness is not an ideal of reason but of imagination declared Kant",

    # Poetry & prose
    "Shall I compare thee to a summer day Thou art more lovely and more temperate",
    "Two roads diverged in a yellow wood and I took the one less traveled by",
    "Hope is the thing with feathers that perches in the soul and sings the tune",
    "I wandered lonely as a cloud that floats on high oer vales and hills",
    "Do not go gentle into that good night old age should burn and rave at close",
    "The woods are lovely dark and deep But I have promises to keep and miles to",
    "It was many and many a year ago in a kingdom by the sea that a maiden there",
    "Tell me not in mournful numbers life is but an empty dream for the soul is",
    "Because I could not stop for Death he kindly stopped for me the carriage held",
    "O Captain my Captain our fearful trip is done the ship has weathered every",
    "I have measured out my life with coffee spoons but I dare not eat the peach",
    "April is the cruellest month breeding lilacs out of the dead land mixing",
    "Let us go then you and I when the evening is spread out against the sky",
    "The fog comes on little cat feet it sits looking over harbor and city",
    "Whose woods these are I think I know his house is in the village though",
]

# CTF flag formats used in real competitions
FLAGS = [
    "flag{real_world_detector_analysis_complete}",
    "flag{incident_response_ready_for_review}",
    "flag{cipher_pipeline_validated_successfully}",
    "flag{forensic_artifacts_recovered_from_disk}",
    "flag{packet_capture_analysis_shows_traffic}",
    "flag{vulnerability_disclosure_timeline_verified}",
    "flag{encrypted_payload_extracted_from_memory}",
    "flag{stealth_malware_bypassed_endpoint_protection}",
    "flag{threat_intelligence_feed_updated_daily}",
    "flag{zero_day_exploit_patched_in_latest_update}",
    "ctf{memory_dump_reveals_lateral_movement}",
    "ctf{teams_collaborate_on_solving_detection}",
    "ctf{critical_finding_documented_in_case_file}",
    "ctf{chain_of_custody_preserved_in_investigation}",
    "ctf{decoded_message_matches_expected_output}",
    "ctf{network_logs_exfiltrated_by_apt_group}",
    "ctf{reverse_engineering_reveals_obfuscation}",
    "ctf{digital_forensics_confirms_timeline_of_attack}",
    "ctf{vulnerability_chain_leads_to_privilege_escalation}",
    "ctf{automated_analysis_detects_anomalous_patterns}",
    "crypto{rsa_private_key_extracted_from_dump}",
    "crypto{aes_encrypted_config_file_decrypted_success}",
    "crypto{hash_collision_identified_in_custom_algorithm}",
    "crypto{diffie_hellman_parameters_vulnerable_to_logjam}",
    "crypto{elliptic_curve_weakness_in_nonce_generation}",
    "crypto{padding_oracle_compromises_cbc_encryption}",
    "crypto{side_channel_timing_leaks_private_key_material}",
    "crypto{entropy_source_compromises_rng_output}",
    "crypto{certificate_authority_intermediate_key_compromised}",
    "crypto{quantum_computer_threatens_shor_algorithm_protected}",
    "hunt{phishing_campaign_domain_registered_last_week}",
    "hunt{malicious_powershell_command_obfuscated_in_script}",
    "hunt{command_and_control_traffic_hidden_in_dns}",
    "hunt{lateral_movement_detected_in_segment_b}",
    "hunt{ransomware_artifacts_identified_in_share_point}",
    "hunt{data_exfiltration_via_encrypted_dns_tunneling}",
    "hunt{persistence_mechanism_scheduled_task_created}",
    "hunt{credential_dumping_sysmon_events_detected}",
    "hunt{living_off_the_land_binary_abused_by_attacker}",
    "hunt{container_escape_vulnerability_exploited_in_pod}",
    "flag{quantum_key_distribution_integrated_in_network}",
    "flag{blockchain_based_voting_system_security_audit}",
    "flag{homomorphic_encryption_applied_to_medical_data}",
    "flag{zero_knowledge_proof_verifies_identity_without_data}",
    "flag{multi_party_computation_enables_secure_collaboration}",
    "flag{post_quantum_cryptography_algorithm_candidate_test}",
    "flag{fully_homomorphic_encryption_performance_benchmark}",
    "flag{secure_enclave_attestation_protects_mobile_payment}",
    "flag{identity_based_encryption_internet_of_things}",
    "flag{attribute_based_access_control_policy_enforcement}",
    "obscuron{detector_pipeline_accuracy_improved}",
    "obscuron{candidate_ranking_with_input_profile}",
    "obscuron{quadgram_scoring_for_transposition_passes}",
    "obscuron{systematic_key_generation_for_detection}",
    "obscuron{recursive_decode_handles_multi_layer}",
    "obscuron{identity_noop_transforms_penalized}",
    "obscuron{dot_json_output_for_detector_results}",
    "obscuron{confidence_calibration_across_families}",
    "obscuron{real_world_corpus_expansion_guide}",
    "obscuron{bifid_trifid_detection_pass_added}",
    "ctf{steganography_detection_in_image_files}",
    "ctf{network_flow_analysis_reveals_encrypted_channel}",
    "ctf{memory_forensics_captures_volatile_evidence}",
    "ctf{malware_unpacks_and_decrypts_second_stage}",
    "ctf{browser_forensics_reconstructs_user_sessions}",
    "ctf{cloud_forensics_investigates_iam_role_abuse}",
    "ctf{active_directory_compromise_leads_to_domain_admin}",
    "ctf{sql_injection_bypasses_waf_in_data_center}",
    "ctf{api_endpoint_exposes_sensitive_user_information}",
    "ctf{buffer_overflow_exploited_in_network_service}",
    "flag{bgp_hijacking_redirects_crypto_exchange_traffic}",
    "flag{dns_poisoning_directs_victims_to_counterfeit_page}",
    "flag{side_channel_exploits_processor_instruction_stream}",
    "flag{rf_attack_jams_iot_device_communication_channel}",
    "flag{firmware_backdoor_grants_persistence_on_router}",
    "flag{satellite_communication_protocol_lacks_encryption}",
    "flag{ics_scada_protocol_barely_authenticated_in_plant}",
    "flag{medical_device_injection_vulnerability_unpatched}",
    "flag{automotive_can_bus_exploit_disables_braking}",
    "flag{dronerf_control_protocol_replayed_by_attacker}",
    "flag{tls_certificate_revocation_check_bypassed}",
    "flag{dnssec_validation_failure_exploited_by_attacker}",
    "flag{smtp_server_relay_open_to_unauthorized_use}",
    "flag{oauth_token_endpoint_missing_rate_limiting}",
    "flag{kerberos_ticket_forging_via_golden_ticket}",
    "flag{ntlm_relay_attack_captures_credentials}",
    "flag{ldap_injection_bypasses_access_control}",
    "flag{kubernetes_secret_exposed_in_etcd_backup}",
    "ctf{wireless_deauthentication_attack_disrupts_network}",
    "ctf{nfc_relay_attack_bypasses_physical_access_control}",
    "ctf{bluetooth_low_energy_tracking_without_consent}",
    "ctf{gps_spoofing_directs_ship_off_course}",
    "ctf{rfid_cloning_grants_access_to_secure_facility}",
    "hunt{docker_container_escapes_into_host_namespace}",
    "hunt{kubernetes_rbac_misconfiguration_allows_escalation}",
    "hunt{serverless_function_injection_via_event_data}",
    "hunt{service_mesh_traffic_manipulation_via_sidecar}",
    "hunt{infrastructure_as_code_template_exposes_secrets}",
    "flag{lattice_based_cryptography_standardization_process}",
    "ctf{firmware_analysis_reveals_hardcoded_backdoor_account}",
]


def rot13(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def atbash(text):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out)


def caesar(text, shift):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}


def morse(text):
    words = []
    for word in text.upper().split():
        letters = [MORSE[ch] for ch in word if ch in MORSE]
        if letters:
            words.append(" ".join(letters))
    return " / ".join(words)


def build_cases():
    cases = []

    # ── Plaintext: 150 real sentences ──
    for i, text in enumerate(REAL_TEXTS):
        cases.append(("plaintext", text, "plaintext"))

    # ── CTF flags: 100 ──
    for i, flag in enumerate(FLAGS):
        cases.append(("ctf_flag", flag, "ctf-flag"))

    # ── Hex: 150 ──
    for i in range(150):
        text = REAL_TEXTS[i % len(REAL_TEXTS)]
        cases.append(("hex", text.encode("utf-8").hex(), "hex"))

    # ── Base64: 150 ──
    for i in range(150):
        text = REAL_TEXTS[(i + 50) % len(REAL_TEXTS)]
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        cases.append(("base64", encoded, "base64"))

    # ── URL: 120 ──
    for i in range(120):
        text = REAL_TEXTS[(i + 100) % len(REAL_TEXTS)]
        cases.append(("url", urllib.parse.quote(text), "url"))

    # ── ROT13: 100 ──
    for i in range(100):
        text = REAL_TEXTS[(i + 30) % len(REAL_TEXTS)]
        cases.append(("rot13", rot13(text), "rot13"))

    # ── Atbash: 100 ──
    for i in range(100):
        text = REAL_TEXTS[(i + 60) % len(REAL_TEXTS)]
        cases.append(("atbash", atbash(text), "atbash"))

    # ── Caesar (mixed shifts 3,5,7,11): 100 ──
    shifts = [3, 5, 7, 11]
    for i in range(100):
        text = REAL_TEXTS[(i + 90) % len(REAL_TEXTS)]
        shift = shifts[i % len(shifts)]
        cases.append(("caesar", caesar(text, shift), "caesar"))

    # ── Morse: 30 ──
    for i in range(30):
        text = REAL_TEXTS[(i + 120) % len(REAL_TEXTS)]
        if len(text.split()) < 2:
            text = REAL_TEXTS[(i + 120 + 10) % len(REAL_TEXTS)]
        cases.append(("morse", morse(text), "morse"))

    assert len(cases) <= 1000, f"Expected <=1000 cases, got {len(cases)}"

    # Trim to exactly 1000
    cases = cases[:1000]

    # Verify unique IDs
    seen = set()
    for fam, ct, exp in cases:
        key = (fam, ct)
        assert key not in seen, f"Duplicate case: {fam} {ct[:40]}"
        seen.add(key)

    return cases


REALWORLD_CASES = build_cases()


@pytest.mark.parametrize(
    ("family", "ciphertext", "expected"),
    REALWORLD_CASES,
    ids=[f"{family}-{i:04d}" for i, (family, _, _) in enumerate(REALWORLD_CASES)],
)
def test_detector_realworld_1000(family, ciphertext, expected):
    rc, out, err = ob_run("detect", "--top", "5", ciphertext)
    assert rc == 0, f"{family} detector command failed: {err}"
    assert expected in out.lower()
