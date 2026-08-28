import json
from collections import Counter, defaultdict
from pathlib import Path


DATA_DIR = Path(
    "data/external/injecagent/InjecAgent/data"
)

TOOLS_FILE = DATA_DIR / "tools.json"


def load_json(path: Path):
    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        return json.load(f)


def get_tools(data):
    """
    Extract the actual tool definitions from tools.json.

    InjecAgent may organize tools under toolkit entries,
    so this function handles the observed structure.
    """

    tools = []

    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return tools

    # Direct "tools" structure
    if isinstance(data.get("tools"), list):
        return data["tools"]

    # Toolkit -> tools structure
    for value in data.values():

        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    if (
                        "name_for_model" in item
                        or "name_for_human" in item
                        or "description_for_model" in item
                    ):
                        tools.append(item)

        elif isinstance(value, dict):

            nested_tools = value.get("tools")

            if isinstance(nested_tools, list):
                for item in nested_tools:
                    if isinstance(item, dict):
                        tools.append(item)

    return tools


def normalize(value):
    if value is None:
        return ""

    if isinstance(value, str):
        return value.strip()

    return str(value)


def classify_tool(tool):
    """
    Heuristic classification used only for dataset auditing.

    This is NOT the final ToolGuard policy.
    """

    text = " ".join(
        [
            normalize(tool.get("name_for_model")),
            normalize(tool.get("name_for_human")),
            normalize(tool.get("description_for_model")),
            normalize(tool.get("description_for_human")),
        ]
    ).lower()

    categories = []

    # Financial
    financial_keywords = (
        "bank",
        "payment",
        "pay",
        "transfer",
        "deposit",
        "withdraw",
        "money",
        "account",
        "binance",
        "financial",
    )

    if any(
        keyword in text
        for keyword in financial_keywords
    ):
        categories.append("financial")

    # Physical
    physical_keywords = (
        "door",
        "lock",
        "unlock",
        "smart lock",
        "thermostat",
        "physical",
        "device",
        "camera",
    )

    if any(
        keyword in text
        for keyword in physical_keywords
    ):
        categories.append("physical")

    # Communication
    communication_keywords = (
        "send email",
        "send message",
        "sms",
        "message",
        "email",
        "post",
        "tweet",
        "notification",
    )

    if any(
        keyword in text
        for keyword in communication_keywords
    ):
        categories.append("communication")

    # Account / permission
    permission_keywords = (
        "grant",
        "permission",
        "access",
        "authorize",
        "revoke",
        "role",
        "guest",
    )

    if any(
        keyword in text
        for keyword in permission_keywords
    ):
        categories.append("authorization")

    # Destructive
    destructive_keywords = (
        "delete",
        "remove",
        "erase",
        "destroy",
        "cancel",
        "disable",
    )

    if any(
        keyword in text
        for keyword in destructive_keywords
    ):
        categories.append("destructive")

    # Write / modification
    modification_keywords = (
        "create",
        "update",
        "modify",
        "change",
        "set",
        "add",
        "edit",
        "grant",
        "transfer",
        "send",
        "unlock",
        "withdraw",
        "deposit",
        "pay",
    )

    if any(
        keyword in text
        for keyword in modification_keywords
    ):
        categories.append("state_changing")

    # Read-only
    read_keywords = (
        "get",
        "search",
        "find",
        "list",
        "retrieve",
        "read",
        "lookup",
        "view",
    )

    if (
        not categories
        and any(
            keyword in text
            for keyword in read_keywords
        )
    ):
        categories.append("read_only")

    if not categories:
        categories.append("other")

    return categories


def print_tool(tool, index):
    print()
    print(f"--- TOOL {index} ---")

    fields = (
        "name_for_model",
        "name_for_human",
        "toolkit",
        "category",
        "description_for_model",
        "description_for_human",
    )

    for field in fields:

        if field in tool:
            value = tool[field]

            if isinstance(value, str):
                value = value.replace(
                    "\n",
                    " ",
                )

                if len(value) > 400:
                    value = value[:400] + "..."

            print(
                f"{field}: {value}"
            )


def main():

    print("=== INJECAGENT TOOL AUDIT ===")
    print()

    if not TOOLS_FILE.exists():
        raise FileNotFoundError(
            f"Tools file not found: {TOOLS_FILE}"
        )

    raw_data = load_json(
        TOOLS_FILE
    )

    print(
        f"Source file: {TOOLS_FILE}"
    )

    print(
        f"Top-level type: {type(raw_data).__name__}"
    )

    if isinstance(raw_data, dict):
        print(
            "Top-level keys:",
            sorted(raw_data.keys()),
        )

    print()

    # --------------------------------------------------
    # Extract tools
    # --------------------------------------------------

    tools = get_tools(
        raw_data
    )

    print("=== TOOL COUNT ===")
    print(
        f"Extracted tools: {len(tools)}"
    )
    print()

    # --------------------------------------------------
    # Tool fields
    # --------------------------------------------------

    print("=== TOOL FIELDS ===")

    field_counter = Counter()

    for tool in tools:
        if isinstance(tool, dict):
            field_counter.update(
                tool.keys()
            )

    for field, count in field_counter.most_common():
        print(
            f"{field:<30} {count}"
        )

    print()

    # --------------------------------------------------
    # Toolkit distribution
    # --------------------------------------------------

    print("=== TOOLKITS ===")

    toolkit_counter = Counter()

    for tool in tools:

        toolkit = normalize(
            tool.get("toolkit")
        )

        if not toolkit:
            toolkit = "unknown"

        toolkit_counter[
            toolkit
        ] += 1

    for toolkit, count in toolkit_counter.most_common():

        print(
            f"{toolkit:<35} {count}"
        )

    print()

    # --------------------------------------------------
    # Original categories
    # --------------------------------------------------

    print("=== ORIGINAL CATEGORIES ===")

    category_counter = Counter()

    for tool in tools:

        category = normalize(
            tool.get("category")
        )

        if not category:
            category = "unknown"

        category_counter[
            category
        ] += 1

    for category, count in category_counter.most_common():

        print(
            f"{category:<35} {count}"
        )

    print()

    # --------------------------------------------------
    # Security classification
    # --------------------------------------------------

    print("=== SECURITY CLASSIFICATION ===")

    classification_counter = Counter()

    tool_classes = []

    for tool in tools:

        classifications = classify_tool(
            tool
        )

        tool_classes.append(
            (
                tool,
                classifications,
            )
        )

        for classification in classifications:
            classification_counter[
                classification
            ] += 1

    for classification, count in (
        classification_counter.most_common()
    ):

        print(
            f"{classification:<35} {count}"
        )

    print()

    # --------------------------------------------------
    # High-risk candidates
    # --------------------------------------------------

    print("=== HIGH-RISK TOOL CANDIDATES ===")

    high_risk = (
        "financial",
        "physical",
        "authorization",
        "destructive",
    )

    high_risk_tools = []

    for tool, classifications in tool_classes:

        if any(
            category in classifications
            for category in high_risk
        ):
            high_risk_tools.append(
                (
                    tool,
                    classifications,
                )
            )

    print(
        f"High-risk candidates: "
        f"{len(high_risk_tools)}"
    )

    for tool, classifications in high_risk_tools:

        name = (
            tool.get("name_for_model")
            or tool.get("name_for_human")
            or "unknown"
        )

        print(
            f"{name:<45} "
            f"{', '.join(classifications)}"
        )

    print()

    # --------------------------------------------------
    # State-changing tools
    # --------------------------------------------------

    print("=== STATE-CHANGING TOOLS ===")

    state_changing = []

    for tool, classifications in tool_classes:

        if "state_changing" in classifications:

            name = (
                tool.get("name_for_model")
                or tool.get("name_for_human")
                or "unknown"
            )

            state_changing.append(
                name
            )

    print(
        f"State-changing candidates: "
        f"{len(state_changing)}"
    )

    for name in state_changing:
        print(
            f"  - {name}"
        )

    print()

    # --------------------------------------------------
    # Read-only tools
    # --------------------------------------------------

    print("=== READ-ONLY TOOLS ===")

    read_only = []

    for tool, classifications in tool_classes:

        if "read_only" in classifications:

            name = (
                tool.get("name_for_model")
                or tool.get("name_for_human")
                or "unknown"
            )

            read_only.append(
                name
            )

    print(
        f"Read-only candidates: "
        f"{len(read_only)}"
    )

    for name in read_only:
        print(
            f"  - {name}"
        )

    print()

    # --------------------------------------------------
    # Sample tools
    # --------------------------------------------------

    print("=== SAMPLE TOOLS ===")

    for index, tool in enumerate(
        tools[:10],
        start=1,
    ):

        print_tool(
            tool,
            index,
        )

    print()

    # --------------------------------------------------
    # Summary by toolkit + security class
    # --------------------------------------------------

    print(
        "=== TOOLKIT / SECURITY SUMMARY ==="
    )

    summary = defaultdict(
        Counter
    )

    for tool, classifications in tool_classes:

        toolkit = normalize(
            tool.get("toolkit")
        )

        if not toolkit:
            toolkit = "unknown"

        for classification in classifications:

            summary[toolkit][
                classification
            ] += 1

    for toolkit in sorted(summary):

        print()
        print(
            f"[{toolkit}]"
        )

        for classification, count in (
            summary[toolkit].most_common()
        ):

            print(
                f"  {classification:<30}"
                f"{count}"
            )

    print()

    # --------------------------------------------------
    # Dataset interpretation
    # --------------------------------------------------

    print("=== AUDIT INTERPRETATION ===")
    print()
    print(
        "This audit is descriptive only."
    )
    print(
        "The heuristic classifications above "
        "are not the final ToolGuard policy."
    )
    print(
        "ToolGuard should be designed after "
        "comparing these tools with InjecAgent "
        "attack cases and test cases."
    )

    print()
    print("=== DONE ===")


if __name__ == "__main__":
    main()