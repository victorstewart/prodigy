#include <prodigy/mothership/truth.placement.selector.h>
#include <cstdio>
#include <cstdlib>
using namespace ProdigyTruthPlacement;

static void expect(bool value, const char* check) {
  if (!value) { std::fprintf(stderr, "FAIL %s\n", check); std::exit(1); }
}

int main() {
  const ClusterID a = (ClusterID(1) << 100) + 1, b = a+1, c = b+1;
  expect(initial({a}) == std::array<ClusterID,3>{a,a,a}, "one cluster");
  expect(initial({b,a,b}) == std::array<ClusterID,3>{a,b,a}, "two clusters");
  expect(initial({c,b,a}) == std::array<ClusterID,3>{a,b,c}, "three clusters");
  expect(initial({c+1,c,b,a}) == std::array<ClusterID,3>{a,b,c}, "four clusters");
  std::vector<Voter> members{{1,a,true,0},{2,a,true,0},{3,b,false,100}};
  expect(next(members,{a},18,3,109,10).action == Action::wait, "retain missing member during grace");
  auto action = next(members,{a},18,3,110,10);
  auto operation = action.replacement;
  expect(action.action == Action::addLearner &&
         operation.newID == 4 && operation.oldID == 3 && operation.target == a, "repair locally after grace");
  members[1].reachable = false;
  expect(next(members,{a},18,3,200,10).action == Action::wait, "single live voter cannot repair");
  members[1].reachable = true;
  expect(next(members,{a,b},18,4,200,10,&operation).replacement.target == a, "retry preserves learner binding");
  expect(next(members,{a},19,4,200,10,&operation,true,false).action == Action::wait, "wait for catch-up");
  expect(next(members,{a},19,4,200,10,&operation,true,true).action == Action::removeVoter, "remove only after catch-up");
  members.pop_back();
  expect(next(members,{a},20,4,200,10,&operation,true,true).action == Action::promoteLearner, "promote after committed removal");
  members.push_back({4,a,true,0});
  expect(next(members,{a,b},21,4,210,10,&operation).action == Action::retireContainer, "retire old incarnation after promotion");
  expect(next(members,{a},21,4,210,10).action == Action::wait, "stable single site");
  action = next(members,{b,a},21,4,230,10);
  expect(action.action == Action::addLearner && action.replacement.target == b && action.replacement.newID == 5,
         "returning site gets fresh learner");
  members.back() = {5,b,true,0};
  expect(next(members,{a,b},25,5,250,10).action == Action::wait, "stable two-site distribution");
  std::puts("PASS Truth placement, repair grace, quorum loss, replacement ordering and returning site");
}
