from pathlib import Path

from scripts.render_readme_example import generate_example


def test_readme_example_matches_generator():
    example_md = generate_example().strip()
    comment_file = Path("docs/example_comment.md")
    assert comment_file.exists(), "docs/example_comment.md must exist"
    assert comment_file.read_text(encoding="utf-8").strip() == example_md

    readme_content = Path("README.md").read_text(encoding="utf-8")
    assert example_md in readme_content, "README.md must contain the exact generated example"
