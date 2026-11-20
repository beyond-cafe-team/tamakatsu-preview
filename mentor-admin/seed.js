// New demo sessions start from the same profile data as the public list.
window.TAMA_DEMO_SEED = window.MENTORS.map(mentor => ({
  ...mentor,
  photo: '../' + mentor.photo,
}));
