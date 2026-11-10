"""gowitness captures found wherever they are, and their screenshots with them."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from seek.gowitness import results as res
from seek.gowitness.locate import ShotFinder, ShotIndex, find_databases, is_gowitness_db

FIX = Path(__file__).parent / "fixtures" / "gowitness" / "capture.sqlite3"
SHOT = "https---hektor.cc-443.jpeg"          # one of the fixture's file names
URL = "https://hektor.cc:443"


def _db(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(FIX.read_bytes())
    return path


def _image(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\xff\xd8\xff")
    return path


# --- finding databases ------------------------------------------------------


def test_a_capture_is_found_at_any_depth_under_any_name(tmp_path):
    deep = _db(tmp_path / "10.0.0.0-24" / "web" / "shots.sqlite3")
    assert find_databases([tmp_path]) == [deep]


def test_other_sqlite_files_are_passed_over_silently(tmp_path):
    other = tmp_path / "browser.db"
    con = sqlite3.connect(other)
    con.execute("create table cookies (name text)")
    con.commit()
    con.close()
    (tmp_path / "notes.db").write_text("not a database")
    assert find_databases([tmp_path]) == []
    assert not is_gowitness_db(other)


def test_dot_directories_are_not_searched(tmp_path):
    _db(tmp_path / ".cache" / "gowitness.sqlite3")
    assert find_databases([tmp_path]) == []


def test_a_capture_reached_twice_is_listed_once(tmp_path):
    db = _db(tmp_path / "web" / "gowitness.sqlite3")
    assert find_databases([tmp_path, tmp_path / "web"]) == [db]


def test_a_database_named_directly_is_taken(tmp_path):
    db = _db(tmp_path / "anywhere.sqlite3")
    assert find_databases([db]) == [db]


# --- finding screenshots ----------------------------------------------------


def test_the_databases_own_screenshots_come_first(tmp_path):
    db = _db(tmp_path / "web" / "gowitness.sqlite3")
    own = _image(tmp_path / "web" / "screenshots" / SHOT)
    _image(tmp_path / "elsewhere" / SHOT)
    assert ShotFinder(db, ShotIndex([tmp_path]))(SHOT) == own


def test_screenshots_beside_the_database(tmp_path):
    db = _db(tmp_path / "web" / "gowitness.sqlite3")
    beside = _image(tmp_path / "web" / SHOT)
    assert ShotFinder(db)(SHOT) == beside


def test_screenshots_moved_below_the_database(tmp_path):
    db = _db(tmp_path / "web" / "gowitness.sqlite3")
    moved = _image(tmp_path / "web" / "2026-09" / "img" / SHOT)
    assert ShotFinder(db)(SHOT) == moved


def test_screenshots_elsewhere_under_the_directories_given(tmp_path):
    """The database was copied away from the images - common when it is shared."""
    db = _db(tmp_path / "db" / "gowitness.sqlite3")
    away = _image(tmp_path / "captures" / "screenshots" / SHOT)
    assert ShotFinder(db, ShotIndex([tmp_path]))(SHOT) == away


def test_the_copy_nearest_the_database_wins(tmp_path):
    """The same URL captured twice writes the same file name twice."""
    first = _db(tmp_path / "a" / "gowitness.sqlite3")
    _image(tmp_path / "b" / "screenshots" / SHOT)
    near = _image(tmp_path / "a" / "old" / SHOT)
    assert ShotFinder(first, ShotIndex([tmp_path]))(SHOT) == near


def test_an_image_found_nowhere_points_where_it_should_have_been(tmp_path):
    db = _db(tmp_path / "gowitness.sqlite3")
    assert ShotFinder(db, ShotIndex([tmp_path]))(SHOT) == tmp_path / "screenshots" / SHOT


def test_a_path_in_the_database_is_cut_to_its_name(tmp_path):
    """A database is read defensively: `../x` or `/etc/x` in the filename
    column never leaves the capture's directories."""
    db = _db(tmp_path / "scans" / "gowitness.sqlite3")
    secret = _image(tmp_path / "secret.jpeg")
    finder = ShotFinder(db)
    assert finder("../secret.jpeg") == tmp_path / "scans" / "screenshots" / "secret.jpeg"
    assert finder(str(secret)) == tmp_path / "scans" / "screenshots" / "secret.jpeg"


def test_reading_a_moved_capture_resolves_its_screenshot(tmp_path):
    db = _db(tmp_path / "db" / "results.sqlite3")
    away = _image(tmp_path / "images" / SHOT)
    captures, problems = res.read_database(db, ShotFinder(db, ShotIndex([tmp_path])))
    assert problems == []
    assert next(c for c in captures if c.url == URL).shot == away


def test_a_screenshot_directory_still_works(tmp_path):
    db = _db(tmp_path / "gowitness.sqlite3")
    captures, _ = res.read_database(db, tmp_path / "screenshots")
    assert next(c for c in captures if c.url == URL).shot == tmp_path / "screenshots" / SHOT
