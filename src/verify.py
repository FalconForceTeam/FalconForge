import glob
import logging
import os
import usecase
import argparse

def main():
    parser = argparse.ArgumentParser(description='Verify usecase files')
    parser.add_argument('--strict', action='store_true', help='Exit with error code 1 if any warnings occur.')
    parser.add_argument('--analyzer-url', type=str, help='URL of the KQL analyzer service to use for validation. If not given no KQL validation will be performed.')
    parser.add_argument('directory', nargs='?', default='usecases', help='Directory to search for usecase files.')
    args = parser.parse_args()

    glob_pattern = os.path.join(args.directory, '**', 'usecase.yml')
    errors = []
    warnings = []
    total_count = 0
    for filename in glob.glob(glob_pattern, recursive=True):
        total_count += 1
        try:
            # Calls usecase.validate on the loaded data, which raises ValidationError if validation fails
            uc = usecase.Usecase.load_from_file(filename)
            # Check for warnings
            warnings += [f'Warning while validating {filename}: {x}' for x in uc.validate_warnings()]
            # Use the language server if given
            if args.analyzer_url:
                warnings += [f'Warning while validating query syntax for {filename}: {x}' for x in uc.validate_query_syntax(query=uc.data.detection_query, language_server=args.analyzer_url, client=None)]
        except usecase.ValidationError as err:
            errors.append(f'Error while validating {filename}: {err}')

    for warning in warnings:
        logging.warning(warning)

    for error in errors:
        logging.error(error)

    print(f"Validated {total_count} use-case files, {len(errors)} errors, {len(warnings)} warnings.")

    if errors or (args.strict and warnings):
        exit(1)

if __name__ == '__main__':
    main()