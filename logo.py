# stdlib
import curses
# libs
# local


def logo(stdscr, offsety, offsetx):

    logo = (
        '                        11                          ',
        '                       11    111 1     11  1  1 111 ',
        '                      11    1    1    1  1 1  1 1  1',
        '                 1   11  1  1    1    1  1 1  1 1  1',
        '                11 111 11   1    1    1  1 1  1 1  1',
        '             1  1111111     1    1    1  1 1  1 1  1',
        '   1111     11  11111        111 1111  11   11  111 ',
        '     1111  111  111   11                           ',
        '      11111111     1111       1111  111 111     111',
        '        111111  11111        11111  111  111   111 ',
        '      1111    11111         111     111   111 111  ',
        '    111   111 1111111       11      111    11111   ',
        '       11111  11111111      11      111    11111   ',
        '    11111111 1111   1111    11      111     111    ',
        '  111 11111  11       111   11      111     111    ',
        '     11  11  11         11  11      111    11111   ',
        '    11  11  11              11      111    11111   ',
        '  111   11                  11      111   111 111  ',
        ' 11     1                    11111  111  111   111 ',
        '11                            1111  111 111     111',
    )

    for y, line in enumerate(logo):
        for x in range(len(line)):
            if line[x] == '1':
                stdscr.addstr(y + offsety, x + offsetx, ' ', curses.color_pair(2))
