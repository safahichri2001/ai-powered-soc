import sys
from pathlib import Path

import pandas as pd


def normalize_text(text: str) -> str:
    """Normalize text for duplicate detection."""

    return " ".join(
        str(text)
        .strip()
        .lower()
        .split()
    )


def audit_dataset(path: Path) -> None:
    """Audit an external CSV dataset."""

    print("\n=== DATASET AUDIT ===\n")
    print(f"File: {path}")

    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}"
        )

    df = pd.read_csv(path)

    print(f"\nRows:    {len(df)}")
    print(f"Columns: {len(df.columns)}")

    print("\n=== COLUMNS ===\n")

    for column in df.columns:
        print(f"- {column}")

    required_columns = {
        "text",
        "label",
        "category",
        "severity",
    }

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    print("\n=== LABELS ===\n")
    print(df["label"].value_counts(dropna=False).to_string())

    print("\n=== CATEGORIES ===\n")
    print(df["category"].value_counts(dropna=False).to_string())

    print("\n=== SEVERITY ===\n")
    print(df["severity"].value_counts(dropna=False).to_string())

    print("\n=== MISSING VALUES ===\n")
    print(df[[
        "text",
        "label",
        "category",
        "severity",
    ]].isna().sum().to_string())

    print("\n=== EMPTY TEXT ===\n")

    empty_text = (
        df["text"]
        .fillna("")
        .astype(str)
        .str.strip()
        .eq("")
        .sum()
    )

    print(f"Empty prompts: {empty_text}")

    print("\n=== DUPLICATES ===\n")

    exact_duplicates = df["text"].duplicated().sum()

    print(f"Exact text duplicates: {exact_duplicates}")

    normalized = (
        df["text"]
        .fillna("")
        .map(normalize_text)
    )

    normalized_duplicates = normalized.duplicated().sum()

    print(
        f"Normalized text duplicates: "
        f"{normalized_duplicates}"
    )

    print("\n=== PROMPT LENGTH ===\n")

    lengths = df["text"].fillna("").astype(str).str.len()

    print(f"Minimum: {lengths.min()}")
    print(f"Maximum: {lengths.max()}")
    print(f"Mean:    {lengths.mean():.2f}")
    print(f"Median:  {lengths.median():.2f}")

    print("\n=== LABEL × CATEGORY ===\n")

    print(
        pd.crosstab(
            df["label"],
            df["category"],
            margins=True,
        ).to_string()
    )


def main() -> None:
    if len(sys.argv) != 2:
        print(
            "Usage:\n"
            "python -m tests.security.audit_external_dataset "
            "<dataset.csv>"
        )
        raise SystemExit(1)

    dataset_path = Path(sys.argv[1])

    audit_dataset(dataset_path)


if __name__ == "__main__":
    main()