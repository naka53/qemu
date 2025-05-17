gustave_ss = ss.source_set()
gustave_ss.add([files(
  'board.c',
  'state.c',
  'inject.c',
  'child.c',
  'snapshot.c',
  'conf.c'
), declare_dependency(link_args: '-Wl,-lrt')])

specific_ss.add_all(gustave_ss)
