import unittest

from iam_auditor.audit import analyze_policy


class AnalyzePolicyTests(unittest.TestCase):
    def test_detects_full_admin_like_statement(self) -> None:
        findings = analyze_policy(
            {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
        )
        self.assertEqual([finding.rule_id for finding in findings], ["IAM001"])
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_detects_service_wildcard_and_resource_wildcard(self) -> None:
        findings = analyze_policy(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            }
        )
        self.assertEqual(
            [finding.rule_id for finding in findings], ["IAM003", "IAM004"]
        )

    def test_detects_open_resource_policy_and_condition_changes_severity(self) -> None:
        statement = {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example/*",
        }
        no_condition = analyze_policy({"Statement": statement})
        with_condition = analyze_policy(
            {"Statement": {**statement, "Condition": {"Bool": {"aws:SecureTransport": "true"}}}}
        )
        self.assertEqual(no_condition[0].severity, "CRITICAL")
        self.assertEqual(with_condition[0].severity, "HIGH")

    def test_detects_privilege_management_action_case_insensitively(self) -> None:
        findings = analyze_policy(
            {
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "s3:GetObject"],
                    "Resource": "arn:aws:iam::123456789012:role/App",
                }
            }
        )
        self.assertEqual([finding.rule_id for finding in findings], ["IAM006"])
        self.assertIn("iam:passrole", findings[0].detail)

    def test_ignores_deny_and_least_privilege_allow(self) -> None:
        findings = analyze_policy(
            {
                "Statement": [
                    {"Effect": "Deny", "Action": "*", "Resource": "*"},
                    {
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::reports/monthly.csv",
                    },
                ]
            }
        )
        self.assertEqual(findings, [])

    def test_rejects_invalid_document_shapes(self) -> None:
        for document in ([], {}, {"Statement": []}, {"Statement": [None]}):
            with self.subTest(document=document), self.assertRaises(ValueError):
                analyze_policy(document)


if __name__ == "__main__":
    unittest.main()
