from llm_fuzz import FuzzConfig, llm_fuzz


def division(x, y):
    return 1 / (x + y)


def division_wrapper(input_data):
    x = input_data.get("x", 1)
    y = input_data.get("y", 1)
    return division(x, y)


def main():
    print("=" * 60)
    print("LLM-Fuzz Example: Testing Division Function")
    print("=" * 60)

    config = FuzzConfig(
        model="gemini/gemini-2.5-flash",
        max_vulnerabilities=3,
        tests_per_vulnerability=2,
        max_discovery_steps=10,
        verbose=True,
    )

    report = llm_fuzz(
        target_function=division,
        test_function=division_wrapper,
        config=config,
        function_description="Function that divides 1 by input x + input y",
        fuzz_params=["x", "y"],
    )

    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    print(f"\nTotal tests: {report.total_count}")
    print(f"Passed: {report.passed_count}")
    print(f"Failed: {report.failed_count}")
    print(f"Pass rate: {report.pass_rate:.1f}%")
    print(f"Total time: {report.total_time:.2f}s")

    print("\n" + "=" * 60)
    print("Detailed Test Results")
    print("=" * 60)
    for result in report.results:
        status = "❌ FAIL" if not result.passed else "✅ PASS"
        print(f"\n{status} {result.test_name}")
        print(f"  Input: {result.input_value}")
        if result.assertion_code_executed:
            print(f"  Assertion: {result.assertion_code_executed}")
        if not result.passed and result.error:
            print(f"  Error: {result.error}")
        if result.assertion_result:
            print(f"  Result: {result.assertion_result}")

    report_path = report.save_to_file()
    print(f"\nFull report saved to: {report_path}")


if __name__ == "__main__":
    main()
