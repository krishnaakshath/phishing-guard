import os
import sys
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import imagehash

import cache
import models
import threat_intel


def test_check_safe_browsing_returns_none_without_api_key():
    with patch.object(threat_intel, 'SAFE_BROWSING_API_KEY', None):
        assert threat_intel.check_safe_browsing('http://example.com') is None


def test_check_safe_browsing_flags_known_match():
    with patch.object(threat_intel, 'SAFE_BROWSING_API_KEY', 'fake-key'):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {'matches': [{'threatType': 'SOCIAL_ENGINEERING'}]}
        mock_resp.raise_for_status.return_value = None
        with patch('threat_intel.requests.post', return_value=mock_resp):
            result = threat_intel.check_safe_browsing('http://phish.example.com')
    assert result['flagged'] is True
    assert 'SOCIAL_ENGINEERING' in result['threat_types']


def test_check_safe_browsing_degrades_gracefully_on_error():
    with patch.object(threat_intel, 'SAFE_BROWSING_API_KEY', 'fake-key'):
        with patch('threat_intel.requests.post', side_effect=Exception('network down')):
            assert threat_intel.check_safe_browsing('http://example.com') is None


def test_check_openphish_uses_cache_and_matches_url():
    test_url = 'http://known-phish.example.com/login'
    cache.set_cached('openphish_feed', {'urls': [test_url]})

    with patch('threat_intel.requests.get') as mock_get:
        result = threat_intel.check_openphish(test_url)
        mock_get.assert_not_called()  # should hit the cache, not the network

    assert result is True
    assert threat_intel.check_openphish('http://totally-safe.example.com') is False


def test_check_domain_reputation_caches_domain_age_lookup():
    domain = 'cache-test-domain.example'
    threat_intel.threat_intel.remove_from_lists(domain)
    # Cache is persisted to the on-disk SQLite DB, so an earlier test run
    # can leave a stale entry - clear it so this test starts from "no cache".
    conn = models.get_db_connection()
    conn.execute('DELETE FROM scan_cache WHERE cache_key = ?', (f'domain_age:{domain}',))
    conn.commit()
    conn.close()

    with patch.object(threat_intel.ThreatIntelligence, '_check_domain_age',
                       return_value={'age_days': 500}) as mock_age:
        threat_intel.threat_intel.check_domain_reputation(domain)
        assert mock_age.call_count == 1

        cached = cache.get_cached(f'domain_age:{domain}', threat_intel.DOMAIN_INTEL_CACHE_TTL)
        assert cached == {'age_days': 500}


def test_check_favicon_hash_skips_known_brand_domain():
    known_domain = next(iter(threat_intel.KNOWN_FAVICON_HASHES))
    assert threat_intel.check_favicon_hash(known_domain) is None


def test_check_favicon_hash_flags_visual_match_on_unrelated_domain():
    brand_domain, brand_hash = next(iter(threat_intel.KNOWN_FAVICON_HASHES.items()))
    fake_resp = MagicMock()
    fake_resp.content = b'not-a-real-image-but-mocked-below'
    fake_resp.raise_for_status.return_value = None

    with patch('threat_intel.requests.get', return_value=fake_resp), \
         patch('threat_intel.Image.open'), \
         patch('threat_intel.imagehash.phash', return_value=brand_hash):
        result = threat_intel.check_favicon_hash('totally-unrelated-domain.example')

    assert result is not None
    assert result['impersonating'] == brand_domain
    assert result['distance'] == 0


def test_check_favicon_hash_no_match_for_dissimilar_icon():
    brand_domain, brand_hash = next(iter(threat_intel.KNOWN_FAVICON_HASHES.items()))
    # Flip every bit - guaranteed maximum Hamming distance, well above threshold
    far_hash = imagehash.ImageHash(~brand_hash.hash)

    fake_resp = MagicMock()
    fake_resp.content = b'not-a-real-image-but-mocked-below'
    fake_resp.raise_for_status.return_value = None

    with patch('threat_intel.requests.get', return_value=fake_resp), \
         patch('threat_intel.Image.open'), \
         patch('threat_intel.imagehash.phash', return_value=far_hash):
        result = threat_intel.check_favicon_hash('some-other-domain.example')

    assert result is None


def test_check_favicon_hash_returns_none_on_fetch_failure():
    with patch('threat_intel.requests.get', side_effect=Exception('connection refused')):
        assert threat_intel.check_favicon_hash('unreachable-domain.example') is None
