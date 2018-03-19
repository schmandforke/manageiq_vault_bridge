FROM ruby:2.3.1-onbuild

RUN mkdir -p /usr/src/app/data

CMD ["./find_and_replace_secrets.rb"]
