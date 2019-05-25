/* Copyright 2017 R. Thomas
 * Copyright 2017 Quarkslab
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "LIEF/logging++.hpp"
#include "LIEF/ELF/enums.hpp"
namespace LIEF {
  namespace ELF {

    // ============
    // ET_LIEF_DYN
    // ============
    template<>
    Segment& Binary::add_segment<E_TYPE::ET_LIEF_DYN>(const Segment& segment, uint64_t base) {
      Header& header = this->header();



      header.numberof_segments(header.numberof_segments() + 1);

      Segment* new_segment = new Segment{ segment };

      if (segment.file_fixed()) {
        new_segment->datahandler_ = this->datahandler_;
        // If the file offset was provided by the user, we trust it
        uint64_t offset = segment.file_offset();

        DataHandler::Node new_node{
                new_segment->file_offset(),
                new_segment->physical_size(),
                DataHandler::Node::SEGMENT };
        this->datahandler_->add(new_node);
        this->datahandler_->make_hole(offset, new_segment->physical_size());

        new_segment->file_offset(offset);

      }
      if (segment.memory_fixed()) {
        new_segment->virtual_address(segment.virtual_address());
        new_segment->physical_address(new_segment->virtual_address());
      }
      new_segment->alignment(segment.alignment() == 0 ? getpagesize() : segment.alignment());

      // If the segment is a BSS, we don't try to add any data
      if (segment.virtual_size() != 0 and segment.physical_size() == 0) {
        new_segment->virtual_size(segment.virtual_size());
      } else {
        std::vector<uint8_t>&& content = segment.content();

        uint64_t size = align(content.size(), segment.alignment());
        content.resize(size, 0);

        new_segment->physical_size(size);
        new_segment->virtual_size(size);

        new_segment->content(content);
      }

      auto&& it_new_segment_place = std::find_if(
        this->segments_.rbegin(),
        this->segments_.rend(),
        [&new_segment](const Segment* s) {
          return s->type() == new_segment->type();
        });

      if (it_new_segment_place == this->segments_.rend()) {
        this->segments_.push_back(new_segment);
      }
      else {
        const size_t idx = std::distance(std::begin(this->segments_), it_new_segment_place.base());
        this->segments_.insert(std::begin(this->segments_) + idx, new_segment);
      }

      return *new_segment;

    }


    template<class T>
    std::unique_ptr<Binary> Binary::create_lief_dyn_impl(ARCH arch, ELF_CLASS clazz) {
      using Elf_Phdr = typename T::Elf_Phdr;
      using Elf_Ehdr = typename T::Elf_Ehdr;
      using Elf_Shdr = typename T::Elf_Shdr;

      std::unique_ptr<Binary> new_binary{ new Binary{} };
      new_binary->type_ = clazz;

      // Set header
      new_binary->header_.file_type(E_TYPE::ET_LIEF_DYN);
      new_binary->header_.machine_type(arch);
      new_binary->header_.object_file_version(VERSION::EV_CURRENT);
      new_binary->header_.entrypoint(0);


      new_binary->header_.processor_flag(0);

      new_binary->header_.header_size(sizeof(Elf_Ehdr));
      new_binary->header_.program_headers_offset(sizeof(Elf_Ehdr));
      new_binary->header_.program_header_size(sizeof(Elf_Phdr));
      new_binary->header_.section_header_size(sizeof(Elf_Shdr));

      std::string ident = "\x7F";
      new_binary->header_.identity(ident + "ELF");
      new_binary->header_.identity_class(clazz);
      new_binary->header_.identity_data(ELF_DATA::ELFDATA2LSB);
      new_binary->header_.identity_version(VERSION::EV_CURRENT);
      new_binary->header_.identity_os_abi(OS_ABI::ELFOSABI_SYSTEMV);

      new_binary->datahandler_ = new DataHandler::Handler{ std::vector<uint8_t>{} };
      return new_binary;
    }

  }
}
