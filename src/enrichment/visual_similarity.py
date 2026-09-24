"""
visual_similarity.py
Compares a candidate domain's screenshot against the brand's reference
screenshot using perceptual hashing (pHash), returning a similarity score (0.0 to 1.0).
"""

import os
import imagehash
from PIL import Image

DEFAULT_REFERENCE_IMAGE_PATH = "reference_assets/brand_reference_screenshot.png"


def compute_similarity(candidate_screenshot_path, reference_path=None, brand_domain=None):
    """
    Returns a similarity score between 0.0 (completely different) and
    1.0 (identical), based on perceptual hash distance:
      similarity = 1 - (hamming_distance / 64)
    """
    try:
        # Determine appropriate reference image
        ref_to_use = reference_path
        if not ref_to_use and brand_domain:
            clean_brand = brand_domain.lower().replace(".", "_").replace("-", "_")
            brand_specific = f"reference_assets/{clean_brand}_reference.png"
            if os.path.exists(brand_specific):
                ref_to_use = brand_specific

        if not ref_to_use:
            ref_to_use = DEFAULT_REFERENCE_IMAGE_PATH

        if not os.path.exists(ref_to_use) or not os.path.exists(candidate_screenshot_path):
            return 0.0

        reference_img = Image.open(ref_to_use)
        candidate_img = Image.open(candidate_screenshot_path)

        reference_hash = imagehash.phash(reference_img)
        candidate_hash = imagehash.phash(candidate_img)

        distance = reference_hash - candidate_hash
        similarity = 1.0 - (distance / 64.0)

        return round(max(min(similarity, 1.0), 0.0), 4)

    except Exception as e:
        print(f"Error computing visual similarity: {e}")
        return 0.0


if __name__ == "__main__":
    score = compute_similarity(DEFAULT_REFERENCE_IMAGE_PATH)
    print(f"Self-similarity test: {score} (expected: 1.0)")
