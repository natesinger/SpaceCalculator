def validateTLE(tle):
    """Check to see if a TLE is valid."""
    #TODO: COUNT NEWLINES IN TLE
    tle_lines = tle.strip().splitlines()
    name = tle_lines[0].strip()
    second_line = tle_lines[1].strip()
    third_line = tle_lines[2].strip()

    if (len(name) > 24):
        raise ValueError("TLE has a name longer than 24 characters.")

    if not (len(second_line) >= 64 and
        second_line.startswith('1 ') and
        second_line[8] == ' ' and
        second_line[23] == '.' and
        second_line[32] == ' ' and
        second_line[34] == '.' and
        second_line[43] == ' ' and
        second_line[52] == ' ' and
        second_line[61] == ' ' and
        second_line[63] == ' '):
        raise ValueError("TLE second line is invalid.")

    if not (len(third_line) >= 69 and
        third_line.startswith('2 ') and
        third_line[7] == ' ' and
        third_line[11] == '.' and
        third_line[16] == ' ' and
        third_line[20] == '.' and
        third_line[25] == ' ' and
        third_line[33] == ' ' and
        third_line[37] == '.' and
        third_line[42] == ' ' and
        third_line[46] == '.' and
        third_line[51] == ' '):
        raise ValueError("TLE third line is invalid.")

    if not (second_line[2:7] == third_line[2:7] ):
        raise ValueError("Satellite number in TLE lines two and three do not match.")
        
    return name, second_line, third_line