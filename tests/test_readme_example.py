from pathlib import Path

from scripts.render_readme_example import generate_block_example, generate_example


def test_readme_examples_match_generators():
    warn_md = generate_example().strip()
    warn_file = Path("docs/example_comment.md")
    assert warn_file.exists(), "docs/example_comment.md must exist"
    assert warn_file.read_text(encoding="utf-8").strip() == warn_md

    block_md = generate_block_example().strip()
    block_file = Path("docs/example_block_comment.md")
    assert block_file.exists(), "docs/example_block_comment.md must exist"
    assert block_file.read_text(encoding="utf-8").strip() == block_md

    readme_content = Path("README.md").read_text(encoding="utf-8")
    assert warn_md in readme_content, "README.md must contain the exact generated WARN example"
    assert block_md in readme_content, "README.md must contain the exact generated BLOCK example"
    assert "payload file removed" in readme_content
