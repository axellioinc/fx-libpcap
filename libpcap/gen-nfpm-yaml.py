# This script must be run from the project root directory for now. It reads the
# nfpm.yaml file and spits out a yaml file nfpm should actually use.
import argparse
import yaml
import os
import sys

def read_version_file(filename):
    with open(filename, 'r') as file:
        version = file.read().rstrip()
        return version
    return None

def read_yaml_base(filename):
    with open(filename, 'r') as file:
        data = yaml.safe_load(file)
        return data
    return None

def get_dir_listing(path):
    dirlist = []
    for root, dirn, files in os.walk(path):
        relpath = os.path.relpath(root, path)
        for file in files:
            dirlist.append(os.path.join(relpath, file))
    return dirlist

def print_dir_listing(args):
    filelist = []
    data = {}
    data['contents'] = []
    filelist = get_dir_listing(args.list)
    for file in filelist:
        full_path = os.path.join('{{BUILD-DIR}}', file)
        reloc_path = os.path.join('/', file)
        data['contents'].append({'src' : full_path, 'dst' : reloc_path})
    print(yaml.dump(data), end="")

def print_yaml_template(args, version):
    # Must have a template file
    data = read_yaml_base(args.template)
    if version:
        data['version'] = version
    if args.template:
        for entry in data['contents']:
            entry['src'] = entry['src'].replace('{{BUILD-DIR}}', args.build_dir)
    print(yaml.dump(data), end="")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', metavar='<directory>', help='Generate a yaml file listing for an nfpm spec file with root of <directory>')
    parser.add_argument('--template', default='template.yaml', help='template yaml file to start with')
    parser.add_argument('--build-dir', help='build directory (root)')
    parser.add_argument('--version-file', help='version file to read from')
    args = parser.parse_args()

    # Read VERSION file if possible
    version = ''
    if args.version_file:
        version = read_version_file(args.version_file)

    if args.list:
        print_dir_listing(args)
    elif args.template:
        print_yaml_template(args, version)
    else:
        sys.stderr.write("Invalid command")

if __name__ == "__main__":
    main()
