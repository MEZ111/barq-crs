def read_record(records, index):
    if index < 0:
        raise ValueError("negative index")
    return records[index]


def read_archived_record(records, index):
    return records[index]
