"""
Backend API Tests for Nilphamari Content App
Tests: Auth, Content CRUD, Admin workflows, Favorites, Search/Filter, Stats
"""
import pytest
import requests
import os
from pathlib import Path
from dotenv import load_dotenv

# Load frontend .env to get EXPO_PUBLIC_BACKEND_URL
frontend_env = Path(__file__).parent.parent.parent / "frontend" / ".env"
if frontend_env.exists():
    load_dotenv(frontend_env)

BASE_URL = os.environ.get('EXPO_PUBLIC_BACKEND_URL', 'https://nilphamari-content.preview.emergentagent.com').rstrip('/')

# Test credentials from /app/memory/test_credentials.md
ADMIN_EMAIL = "admin@nilphamari.bd"
ADMIN_PASSWORD = "admin123"
TEST_USER_EMAIL = "testuser@example.com"
TEST_USER_PASSWORD = "test1234"


@pytest.fixture
def api_client():
    """Shared requests session"""
    session = requests.Session()
    session.headers.update({"Content-Type": "application/json"})
    return session


@pytest.fixture
def admin_token(api_client):
    """Get admin JWT token"""
    response = api_client.post(f"{BASE_URL}/api/auth/login", json={
        "email": ADMIN_EMAIL,
        "password": ADMIN_PASSWORD
    })
    if response.status_code != 200:
        pytest.skip(f"Admin login failed: {response.status_code}")
    return response.json()["token"]


@pytest.fixture
def user_token(api_client):
    """Create test user and get token"""
    # Try to register (may already exist)
    api_client.post(f"{BASE_URL}/api/auth/register", json={
        "name": "Test User",
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    })
    # Login
    response = api_client.post(f"{BASE_URL}/api/auth/login", json={
        "email": TEST_USER_EMAIL,
        "password": TEST_USER_PASSWORD
    })
    if response.status_code != 200:
        pytest.skip(f"User login failed: {response.status_code}")
    return response.json()["token"]


class TestHealthCheck:
    """Basic health check"""
    
    def test_api_root(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/")
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Nilphamari" in data["message"]
        print("✓ API root endpoint working")


class TestAuth:
    """Authentication endpoints"""
    
    def test_admin_login_success(self, api_client):
        response = api_client.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": ADMIN_PASSWORD
        })
        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert "user" in data
        assert data["user"]["email"] == ADMIN_EMAIL
        assert data["user"]["role"] == "admin"
        print(f"✓ Admin login successful: {data['user']['email']}")
    
    def test_login_wrong_password(self, api_client):
        response = api_client.post(f"{BASE_URL}/api/auth/login", json={
            "email": ADMIN_EMAIL,
            "password": "wrongpassword"
        })
        assert response.status_code == 401
        print("✓ Wrong password rejected correctly")
    
    def test_register_new_user(self, api_client):
        import uuid
        unique_email = f"newuser_{uuid.uuid4().hex[:8]}@test.com"
        response = api_client.post(f"{BASE_URL}/api/auth/register", json={
            "name": "New User",
            "email": unique_email,
            "password": "newpass123"
        })
        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert "user" in data
        assert data["user"]["email"] == unique_email
        assert data["user"]["role"] == "user"
        print(f"✓ User registration successful: {unique_email}")
    
    def test_register_duplicate_email(self, api_client):
        response = api_client.post(f"{BASE_URL}/api/auth/register", json={
            "name": "Admin Duplicate",
            "email": ADMIN_EMAIL,
            "password": "somepass"
        })
        assert response.status_code == 400
        print("✓ Duplicate email rejected")
    
    def test_get_current_user(self, api_client, admin_token):
        response = api_client.get(
            f"{BASE_URL}/api/auth/me",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == ADMIN_EMAIL
        assert data["role"] == "admin"
        print(f"✓ GET /api/auth/me working: {data['email']}")
    
    def test_auth_me_without_token(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/auth/me")
        assert response.status_code == 401
        print("✓ Unauthorized access blocked")


class TestContent:
    """Content listing and filtering"""
    
    def test_get_all_content(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 10  # 10 seeded items
        print(f"✓ GET /api/content returns {len(data)} items")
    
    def test_filter_by_category_tourism(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content?category=tourism")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert all(item["category"] == "tourism" for item in data)
        print(f"✓ Category filter 'tourism' returns {len(data)} items")
    
    def test_filter_by_category_history(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content?category=history")
        assert response.status_code == 200
        data = response.json()
        assert all(item["category"] == "history" for item in data)
        print(f"✓ Category filter 'history' returns {len(data)} items")
    
    def test_filter_by_category_business(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content?category=business")
        assert response.status_code == 200
        data = response.json()
        assert all(item["category"] == "business" for item in data)
        print(f"✓ Category filter 'business' returns {len(data)} items")
    
    def test_filter_by_category_news(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content?category=news")
        assert response.status_code == 200
        data = response.json()
        assert all(item["category"] == "news" for item in data)
        print(f"✓ Category filter 'news' returns {len(data)} items")
    
    def test_filter_featured(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content?featured=true")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert all(item["is_featured"] is True for item in data)
        print(f"✓ Featured filter returns {len(data)} items")
    
    def test_search_by_query(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content?q=নীলসাগর")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # Should find "নীলসাগর দিঘী" in seeded data
        assert len(data) > 0
        print(f"✓ Search 'নীলসাগর' returns {len(data)} items")
    
    def test_get_single_content(self, api_client):
        # First get list to get an ID
        list_response = api_client.get(f"{BASE_URL}/api/content")
        items = list_response.json()
        if len(items) == 0:
            pytest.skip("No content items to test")
        
        content_id = items[0]["id"]
        response = api_client.get(f"{BASE_URL}/api/content/{content_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == content_id
        assert "title" in data
        assert "description" in data
        print(f"✓ GET single content: {data['title'][:30]}...")
    
    def test_get_nonexistent_content(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/content/nonexistent-id-12345")
        assert response.status_code == 404
        print("✓ Nonexistent content returns 404")


class TestContentCreation:
    """Content creation with auth"""
    
    def test_create_content_as_user_pending(self, api_client, user_token):
        """User-created content should be 'pending'"""
        response = api_client.post(
            f"{BASE_URL}/api/content",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "title": "TEST_User Content",
                "description": "This is a test content created by user",
                "category": "tourism",
                "images": [],
                "video_url": "",
                "location": {"name": "Test Location", "lat": 25.93, "lng": 88.85}
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"
        assert data["title"] == "TEST_User Content"
        print(f"✓ User content created with status: {data['status']}")
        
        # Verify it's NOT in public listing (status=approved by default)
        list_response = api_client.get(f"{BASE_URL}/api/content")
        public_items = list_response.json()
        assert not any(item["id"] == data["id"] for item in public_items)
        print("✓ Pending content not in public listing")
        
        return data["id"]
    
    def test_create_content_as_admin_approved(self, api_client, admin_token):
        """Admin-created content should be 'approved'"""
        response = api_client.post(
            f"{BASE_URL}/api/content",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "title": "TEST_Admin Content",
                "description": "This is a test content created by admin",
                "category": "news",
                "images": [],
                "video_url": ""
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "approved"
        assert data["title"] == "TEST_Admin Content"
        print(f"✓ Admin content created with status: {data['status']}")
        
        # Verify it IS in public listing
        list_response = api_client.get(f"{BASE_URL}/api/content")
        public_items = list_response.json()
        assert any(item["id"] == data["id"] for item in public_items)
        print("✓ Approved content in public listing")
        
        return data["id"]
    
    def test_create_content_without_auth(self, api_client):
        response = api_client.post(f"{BASE_URL}/api/content", json={
            "title": "Unauthorized Content",
            "description": "Should fail",
            "category": "tourism"
        })
        assert response.status_code == 401
        print("✓ Content creation without auth blocked")


class TestAdminWorkflow:
    """Admin approval/rejection workflow"""
    
    def test_get_pending_content_as_admin(self, api_client, admin_token):
        response = api_client.get(
            f"{BASE_URL}/api/admin/content/pending",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        print(f"✓ Admin can view {len(data)} pending items")
    
    def test_get_pending_as_user_forbidden(self, api_client, user_token):
        response = api_client.get(
            f"{BASE_URL}/api/admin/content/pending",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 403
        print("✓ Non-admin blocked from pending endpoint")
    
    def test_approve_content(self, api_client, admin_token, user_token):
        # Create pending content as user
        create_response = api_client.post(
            f"{BASE_URL}/api/content",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "title": "TEST_Content to Approve",
                "description": "Will be approved",
                "category": "tourism"
            }
        )
        content_id = create_response.json()["id"]
        
        # Approve as admin
        approve_response = api_client.put(
            f"{BASE_URL}/api/admin/content/{content_id}/approve",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert approve_response.status_code == 200
        data = approve_response.json()
        assert data["status"] == "approved"
        print(f"✓ Content approved: {data['id']}")
        
        # Verify it's now in public listing
        list_response = api_client.get(f"{BASE_URL}/api/content")
        public_items = list_response.json()
        assert any(item["id"] == content_id for item in public_items)
        print("✓ Approved content now public")
    
    def test_reject_content(self, api_client, admin_token, user_token):
        # Create pending content as user
        create_response = api_client.post(
            f"{BASE_URL}/api/content",
            headers={"Authorization": f"Bearer {user_token}"},
            json={
                "title": "TEST_Content to Reject",
                "description": "Will be rejected",
                "category": "news"
            }
        )
        content_id = create_response.json()["id"]
        
        # Reject as admin
        reject_response = api_client.put(
            f"{BASE_URL}/api/admin/content/{content_id}/reject",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert reject_response.status_code == 200
        data = reject_response.json()
        assert data["status"] == "rejected"
        print(f"✓ Content rejected: {data['id']}")


class TestFavorites:
    """Favorites functionality"""
    
    def test_get_favorites_requires_auth(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/favorites")
        assert response.status_code == 401
        print("✓ Favorites require authentication")
    
    def test_add_and_remove_favorite(self, api_client, user_token):
        # Get a content item
        list_response = api_client.get(f"{BASE_URL}/api/content")
        items = list_response.json()
        if len(items) == 0:
            pytest.skip("No content to favorite")
        content_id = items[0]["id"]
        
        # Add to favorites
        add_response = api_client.post(
            f"{BASE_URL}/api/favorites/{content_id}",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert add_response.status_code == 200
        print(f"✓ Added to favorites: {content_id}")
        
        # Verify in favorites list
        fav_response = api_client.get(
            f"{BASE_URL}/api/favorites",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert fav_response.status_code == 200
        favs = fav_response.json()
        assert any(item["id"] == content_id for item in favs)
        print(f"✓ Favorites list contains {len(favs)} items")
        
        # Remove from favorites
        remove_response = api_client.delete(
            f"{BASE_URL}/api/favorites/{content_id}",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert remove_response.status_code == 200
        print(f"✓ Removed from favorites: {content_id}")
        
        # Verify removed
        fav_response2 = api_client.get(
            f"{BASE_URL}/api/favorites",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        favs2 = fav_response2.json()
        assert not any(item["id"] == content_id for item in favs2)
        print("✓ Favorites list updated after removal")
    
    def test_get_favorite_ids(self, api_client, user_token):
        response = api_client.get(
            f"{BASE_URL}/api/favorites/ids",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "ids" in data
        assert isinstance(data["ids"], list)
        print(f"✓ Favorite IDs endpoint returns {len(data['ids'])} IDs")


class TestStats:
    """Stats endpoint"""
    
    def test_get_stats(self, api_client):
        response = api_client.get(f"{BASE_URL}/api/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert "tourism" in data
        assert "history" in data
        assert "business" in data
        assert "news" in data
        assert "pending" in data
        print(f"✓ Stats: total={data['total']}, tourism={data['tourism']}, history={data['history']}, business={data['business']}, news={data['news']}, pending={data['pending']}")
