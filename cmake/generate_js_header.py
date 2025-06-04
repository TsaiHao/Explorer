import os
import argparse


def generate_js_header(
    input_js_file: str, output_header_file: str, variable_name: str = "kScriptSource"
):
    with open(input_js_file, "r") as js_file:
        js_content = js_file.read()

    output_dir = os.path.dirname(output_header_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(output_header_file, "w") as header_file:
        header_file.write(
            "// This file is auto-generated from {}\n\n".format(input_js_file)
        )
        header_file.write("#pragma once\n\n")
        header_file.write("#include <string_view>\n\n")
        header_file.write(f'constexpr std::string_view {variable_name} = R"js_code(\n')
        #header_file.write(js_content.replace('"', '\\"').replace("\n", "\\n") + "\n")
        header_file.write(js_content + "\n")
        header_file.write(')js_code";\n')
        print("Header file generated successfully at {}".format(output_header_file))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate a C++ header file from a JavaScript file."
    )
    parser.add_argument(
        "-input_js_file", "-i", type=str, help="Path to the input JavaScript file"
    )
    parser.add_argument(
        "-output_header_file", "-o", type=str, help="Path to the output header file"
    )
    parser.add_argument(
        "-variable_name",
        "-v",
        type=str,
        help="Name of the variable in the header file",
    )

    args = parser.parse_args()
    generate_js_header(args.input_js_file, args.output_header_file, args.variable_name)
